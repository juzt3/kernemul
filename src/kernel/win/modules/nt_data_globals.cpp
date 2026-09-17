#include "ntoskrnl.hpp"
#include "../win_kernel.hpp"
#include "../defs.hpp"
#include "../per_cpu.hpp"
#include "../user_setup.hpp"
#include "../string.hpp"
#include "../../../util/log.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>

// ntoskrnl's own initialisers never ran, so every global it would have filled in at boot still
// holds whatever the PE image carried. Most of those are zero, which is merely useless -- but a
// few are zero in a way that says something false, and KdDebuggerNotPresent is the worst of
// them: it is a BOOLEAN where TRUE means "no debugger", so reading 0 tells every driver that
// asks that a kernel debugger is attached.
//
// Only the globals whose right value the emulator actually owns are written here. Ones the
// image already has right -- MmHighestUserAddress, MmSystemRangeStart, MmUserProbeAddress,
// NtBuildNumber, NtGlobalFlag -- are left alone: they are per-build, per-arch facts, and this
// repo ships two image sets, so a hardcode here would be a wrong answer waiting for someone to
// swap the guest filesystem.
//
// MmPteBase names the base of the recursive page-table self map, which only x86-64 has one of;
// win_target::pte_base is zero on an architecture that does not.

namespace
{

// `exported` says how loud a miss is. A missing export means the wrong ntoskrnl and is worth
// shouting about; a pdb-only symbol is simply absent on an arch with no cached pdb -- fs_arm64
// has none -- and the run is still correct, so warning per symbol there would only teach people
// to ignore warnings.
//
// The bounds check is not optional: write_mem throws on an unmapped va, and all of this runs
// inside win_kernel_state's constructor, where an escaping exception kills startup with nothing
// in the log to say why.
template <typename T>
	requires std::is_trivially_copyable_v<T>
addr_t write_global(addr_space& space, const proc_module& mod, const std::string_view name,
	const T& value, const bool exported = true)
{
	const auto va = mod.find_symbol(name);

	if (!va)
	{
		if (exported)
			LOG_ERR("{} does not export '{}', so it keeps whatever the image holds",
				mod.name, name);
		else
			LOG_INFO("no symbol for '{}' in {}, so it keeps whatever the image holds",
				name, mod.name);

		return 0;
	}

	if (!mod.contains_addr(*va) || !mod.contains_addr(*va + sizeof(T) - 1))
	{
		LOG_ERR("'{}' resolves to 0x{:X}, which is outside {}", name, *va, mod.name);
		return 0;
	}

	space.write_mem(*va, value);

	if constexpr (std::is_integral_v<T>)
		LOG_INFO("{}!{} at 0x{:X} = 0x{:X}", mod.name, name, *va,
			static_cast<std::uint64_t>(value));
	else
		LOG_INFO("{}!{} at 0x{:X} initialised ({} bytes)", mod.name, name, *va, sizeof(T));

	return *va;
}

// An empty list head points at itself. Zero is the one shape that is never valid: the first
// walker to follow Flink dereferences null.
addr_t init_list_head(addr_space& space, const proc_module& mod, const std::string_view name,
	const bool exported = true)
{
	const auto va = write_global(space, mod, name, _LIST_ENTRY{}, exported);

	if (va)
		space.write_mem(va, guest_links(va, va));

	return va;
}

// A driver walking 0..NumberOfPhysicalPages must not walk off the end, so the array is sized
// from the same constant the guest is told. A zeroed _MMPFN is a coherent lie -- page not
// valid, refcount zero, on no list -- which is the point.
void init_pfn_database(addr_space& space, const proc_module& mod)
{
	constexpr auto bytes = emulated_physical_pages * sizeof(_MMPFN);

	const auto base = space.alloc(bytes, prot_rw | prot_supervisor);

	// Never publish a pointer that was not actually mapped. A bogus non-null one faults at a
	// plausible-looking kernel address and reads as a guest bug; null faults at 0 and is
	// recognisable on sight.
	if (!base)
	{
		LOG_ERR("no room for a {} byte pfn database, so MmPfnDatabase stays null", bytes);
		return;
	}

	if (!write_global<addr_t>(space, mod, "MmPfnDatabase", base, false))
		return;

	const auto read_back = space.read_mem<addr_t>(*mod.find_symbol("MmPfnDatabase"));

	LOG_INFO("pfn database: {} entries of {} bytes at 0x{:X} (read back 0x{:X})",
		emulated_physical_pages, sizeof(_MMPFN), base, read_back);
}

// Ob creates one _OBJECT_TYPE per kind of object it manages and publishes a pointer to each in
// an exported global. Those globals are null in the image, and nothing here ran ObCreateObjectType
// to fill them, so a driver that reads one gets null and dereferences it -- Vanguard reads the
// process type's TotalNumberOfObjects, which is a load through the null pointer at +0x2C.
//
// The type is otherwise empty on purpose: the counts are the only fields anything here could
// answer honestly, and they belong to an object manager that keeps its bookkeeping host side.
addr_t init_object_type(addr_space& space, const proc_module& mod, const std::string_view global,
	const std::u16string_view name)
{
	const auto addr = space.alloc(sizeof(_OBJECT_TYPE), prot_rw | prot_supervisor);

	if (!addr)
	{
		LOG_ERR("no room for an _OBJECT_TYPE, so {} stays null", global);
		return 0;
	}

	_OBJECT_TYPE type{};
	type.Name = win::init_unicode_string(space, name);

	space.write_mem(addr, type);

	// Both lists are empty, and an empty list head points at itself rather than holding zeroes.
	for (const auto head : { addr + offsetof(_OBJECT_TYPE, TypeList),
		addr + offsetof(_OBJECT_TYPE, CallbackList) })
	{
		space.write_mem(head, guest_links(head, head));
	}

	if (!write_global<addr_t>(space, mod, global, addr))
		return 0;

	return addr;
}

}

void modules::init_ntoskrnl_globals(win_kernel_state& state, proc_module& mod)
{
	auto& space = state.kernel_space();

	// The headline. Everything else here is a convenience; this one is a correction.
	write_global<std::uint8_t>(space, mod, "KdDebuggerNotPresent", 1);

	// Both already read 0 out of the image, and 0 is what they should say. Written anyway so
	// the emulator's debugger story is stated once, in one place, rather than being two thirds
	// accidental -- swap in a differently built ntoskrnl and the story does not silently change.
	write_global<std::uint8_t>(space, mod, "KdDebuggerEnabled", 0);
	write_global<std::uint8_t>(space, mod, "KdEnteredDebugger", 0);

	// The image's own copy is a link-time guess; the real base is wherever it just mapped.
	write_global<addr_t>(space, mod, "PsNtosImageBase", mod.addr, false);

	// A driver can reach the same fact two ways, so the global and KeQueryTimeIncrement have to
	// agree -- a zero here against 156250 from the export is a kernel contradicting itself.
	write_global<std::uint32_t>(space, mod, "KeTimeIncrement", clock_increment_100ns, false);
	write_global<std::uint32_t>(space, mod, "ExpTickCountMultiplier",
		default_tick_count_multiplier, false);

	init_list_head(space, mod, "PiDDBCacheList", false);
	init_list_head(space, mod, "CallbackListHead", false);
	init_list_head(space, mod, "ExpCallbackListHead", false);

	// The lock that guards the cache list above. Initialised the way ExInitializeResourceLite
	// initialises one, so a driver that acquires it finds a well formed object.
	if (const auto va = write_global(space, mod, "PiDDBLock", _ERESOURCE{}, false))
	{
		const auto head = va + offsetof(_ERESOURCE, SystemResourcesList);
		space.write_mem(head, guest_links(head, head));
	}

	// The slot this names is the one the mmu actually points back at itself.
	if constexpr (win_target::pte_base)
		write_global<addr_t>(space, mod, "MmPteBase", win_target::pte_base, false);

	init_pfn_database(space, mod);

	// The four ObGetObjectType can name, so that reading a type back gives the same pointer the
	// global holds rather than null.
	init_object_type(space, mod, "PsProcessType", u"Process");
	init_object_type(space, mod, "PsThreadType", u"Thread");
	init_object_type(space, mod, "IoFileObjectType", u"File");
	init_object_type(space, mod, "MmSectionObjectType", u"Section");

	// The mapped ntoskrnl is the authority on its own build, and NtBuildNumber is exported on
	// both arches so this needs no pdb. The low 16 bits are the build; the rest are flags.
	if (const auto va = mod.find_symbol("NtBuildNumber"); va && mod.contains_addr(*va))
	{
		if (const auto build = space.read_mem<std::uint32_t>(*va) & 0xFFFF)
		{
			state.nt_build_number = build;
			LOG_INFO("{} reports build {}", mod.name, build);
		}
		else
		{
			LOG_WARN("{}!NtBuildNumber reads 0, so build {} is reported instead",
				mod.name, state.nt_build_number);
		}
	}

	// These three cannot be written yet: KiProcessorBlock is indexed by cpu number and holds
	// KPRCB pointers, and the other two want the final count -- none of which exists until
	// create_vcpus runs. Their addresses are cached now because the module is not kept.
	// Not written, only located: KPCR.LockArray points an entry at it, and that is built per
	// cpu, after this runs.
	state.non_paged_pool_lock = mod.find_symbol("NonPagedPoolLock").value_or(0);

	state.late_globals.ki_processor_block = mod.find_symbol("KiProcessorBlock").value_or(0);
	state.late_globals.ke_number_processors = mod.find_symbol("KeNumberProcessors").value_or(0);
	state.late_globals.ke_active_processors = mod.find_symbol("KeActiveProcessors").value_or(0);
}
