#include "nt_vm_ops.hpp"
#include "../win_kernel.hpp"
#include "../mdl.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <algorithm>
#include <array>
#include <cstring>

namespace
{

// AllocationType, of which only the two that decide whether pages appear
// matter here: there is no reserved-but-not-committed state to keep.
enum allocation_type : std::uint32_t
{
	mem_commit  = 0x00001000,
	mem_reserve = 0x00002000,
	mem_release = 0x00008000,
	mem_free    = 0x00010000,
};

// PAGE_* protection, and what it means to the emulator's mmu.
enum page_protection : std::uint32_t
{
	page_noaccess          = 0x01,
	page_readonly          = 0x02,
	page_readwrite         = 0x04,
	page_writecopy         = 0x08,
	page_execute           = 0x10,
	page_execute_read      = 0x20,
	page_execute_readwrite = 0x40,
	page_execute_writecopy = 0x80,
};

mem_prot prot_from_page(const std::uint32_t protect)
{
	// The low byte names the access; the flags above it are caching and guard
	// bits that the mmu here has no notion of.
	switch (protect & 0xFF)
	{
	case page_noaccess:          return static_cast<mem_prot>(0);
	case page_readonly:          return prot_read;
	case page_readwrite:
	case page_writecopy:         return prot_rw;
	case page_execute:           return prot_exec;
	case page_execute_read:      return prot_rx;
	case page_execute_readwrite:
	case page_execute_writecopy: return prot_rwx;
	default:                     return prot_rw;
	}
}

std::uint32_t page_from_prot(const mem_prot prot)
{
	const bool w = (prot & prot_write) != 0;
	const bool x = (prot & prot_exec) != 0;

	if (!(prot & prot_read))
		return page_noaccess;

	if (x)
		return w ? page_execute_readwrite : page_execute_read;

	return w ? page_readwrite : page_readonly;
}

// MEMORY_INFORMATION_CLASS, of which only the basic one is answerable from the
// page tables alone.
constexpr std::uint32_t memory_basic_information = 0;

// SECTION_INFORMATION_CLASS.
constexpr std::uint32_t section_basic_information = 0;

#pragma pack(push, 8)
struct memory_basic_information_t
{
	addr_t        base_address;
	addr_t        allocation_base;
	std::uint32_t allocation_protect;
	std::uint32_t partition_id;
	std::uint64_t region_size;
	std::uint32_t state;
	std::uint32_t protect;
	std::uint32_t type;
	std::uint32_t padding;
};

struct section_basic_information_t
{
	addr_t        base_address;
	std::uint32_t allocation_attributes;
	std::uint32_t padding;
	std::int64_t  maximum_size;
};
#pragma pack(pop)

static_assert(sizeof(memory_basic_information_t) == 0x30);
static_assert(sizeof(section_basic_information_t) == 0x18);

// MEM_COMMIT / MEM_FREE as MEMORY_BASIC_INFORMATION reports them.
constexpr std::uint32_t mem_state_commit = 0x1000;
constexpr std::uint32_t mem_state_free = 0x10000;
constexpr std::uint32_t mem_type_private = 0x20000;

// Only the current process is addressable: there is one address space, and a
// handle naming any other has nothing behind it. -1 is the pseudo-handle for
// the caller itself, which is what a driver reaching for its own memory passes.
constexpr std::uint64_t current_process_handle = ~std::uint64_t{0};

bool is_current_process(const std::uint64_t handle)
{
	return handle == 0 || handle == current_process_handle;
}

}

// Virtual memory and the sections it can be made out of. The page tables behind
// these are the guest's own, so an address handed out here is one the guest
// faults against exactly as it would on real hardware.
void modules::register_ntoskrnl_vm_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// The allocation lands where the address space puts it: the caller names a
	// preferred base, and nothing here can honour one, so the base it gets back
	// is the one it has to use.
	auto allocate = [](vcpu& cpu, const std::uint64_t process_handle,
		emu_object<addr_t> base_address, emu_object<std::uint64_t> region_size,
		const std::uint32_t allocation_type, const std::uint32_t protect,
		const std::string_view who) -> NTSTATUS
	{
		if (!is_current_process(process_handle))
		{
			THREAD_LOG_WARN("{}: process handle 0x{:X} is not this process, and there is no "
				"other address space", who, process_handle);
			return STATUS_INVALID_HANDLE;
		}

		if (!base_address || !region_size)
			return STATUS_INVALID_PARAMETER;

		const auto requested = region_size.read();

		if (!requested)
			return STATUS_INVALID_PARAMETER;

		const auto wanted = base_address.read();
		const auto size = (requested + mdl_page_size - 1) & ~static_cast<std::uint64_t>(mdl_page_size - 1);

		// Reserve without commit still gets pages: there is no reserved state
		// to hold an address range in, and a caller that reserves then commits
		// the same range would otherwise be handed two different bases.
		if (!(allocation_type & (mem_commit | mem_reserve)))
			return STATUS_INVALID_PARAMETER;

		auto& space = *cpu.curr_addr_space();
		addr_t addr = 0;

		try
		{
			addr = space.alloc(size, prot_from_page(protect) | prot_supervisor);
		}
		catch (const std::exception& e)
		{
			THREAD_LOG_ERR("{}: cannot allocate {} bytes: {}", who, size, e.what());
			return STATUS_NO_MEMORY;
		}

		if (!addr)
			return STATUS_NO_MEMORY;

		if (wanted && wanted != addr)
			THREAD_LOG_WARN("{}: wanted 0x{:X}, allocated 0x{:X} -- the address space picks",
				who, wanted, addr);

		base_address.write(addr);
		region_size.write(size);

		THREAD_LOG_INFO("{}(size={}, type=0x{:X}, protect=0x{:X}) -> 0x{:X}",
			who, size, allocation_type, protect, addr);

		return STATUS_SUCCESS;
	};

	auto allocate_vm = [allocate](vcpu& cpu, const std::uint64_t process_handle,
		emu_object<addr_t> base_address, [[maybe_unused]] const std::uint64_t zero_bits,
		emu_object<std::uint64_t> region_size, const std::uint32_t allocation_type,
		const std::uint32_t protect) -> NTSTATUS
	{
		return allocate(cpu, process_handle, base_address, region_size, allocation_type,
			protect, "NtAllocateVirtualMemory");
	};

	// The extended parameters describe which node or partition the pages should
	// come from. There is one of each, so they are only reported.
	auto allocate_vm_ex = [allocate](vcpu& cpu, const std::uint64_t process_handle,
		emu_object<addr_t> base_address, emu_object<std::uint64_t> region_size,
		const std::uint32_t allocation_type, const std::uint32_t protect,
		const addr_t extended_parameters, const std::uint32_t extended_parameter_count) -> NTSTATUS
	{
		if (extended_parameter_count)
			THREAD_LOG_WARN("NtAllocateVirtualMemoryEx: ignoring {} extended parameter(s) at 0x{:X}",
				extended_parameter_count, extended_parameters);

		return allocate(cpu, process_handle, base_address, region_size, allocation_type,
			protect, "NtAllocateVirtualMemoryEx");
	};

	auto free_vm = [](vcpu& cpu, const std::uint64_t process_handle,
		emu_object<addr_t> base_address, emu_object<std::uint64_t> region_size,
		const std::uint32_t free_type) -> NTSTATUS
	{
		if (!is_current_process(process_handle))
			return STATUS_INVALID_HANDLE;

		if (!base_address)
			return STATUS_INVALID_PARAMETER;

		const auto base = mdl_page_base(base_address.read());
		auto size = region_size ? region_size.read() : 0;

		// MEM_RELEASE takes down the whole allocation and demands a size of
		// zero; MEM_DECOMMIT takes down what the caller names.
		if (free_type & mem_release)
		{
			if (size)
				return STATUS_INVALID_PARAMETER;

			// The address space has no record of how long the run was, so the
			// release takes down the page the base names and no more.
			size = mdl_page_size;
		}

		if (!size)
			return STATUS_INVALID_PARAMETER;

		auto& space = *cpu.curr_addr_space();

		try
		{
			space.mmu_->unmap_virt(space, base, size);
		}
		catch (const std::exception& e)
		{
			THREAD_LOG_WARN("NtFreeVirtualMemory: 0x{:X} is not mapped: {}", base, e.what());
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		if (region_size)
			region_size.write(size);

		THREAD_LOG_INFO("NtFreeVirtualMemory(0x{:X}, {} bytes, type=0x{:X})", base, size, free_type);

		return STATUS_SUCCESS;
	};

	auto protect_vm = [](vcpu& cpu, const std::uint64_t process_handle,
		emu_object<addr_t> base_address, emu_object<std::uint64_t> region_size,
		const std::uint32_t new_protect, emu_object<std::uint32_t> old_protect) -> NTSTATUS
	{
		if (!is_current_process(process_handle))
			return STATUS_INVALID_HANDLE;

		if (!base_address || !region_size)
			return STATUS_INVALID_PARAMETER;

		const auto requested = base_address.read();
		const auto base = mdl_page_base(requested);
		const auto size = (region_size.read() + (requested - base) + mdl_page_size - 1)
			& ~static_cast<std::uint64_t>(mdl_page_size - 1);

		auto& space = *cpu.curr_addr_space();

		// The old protection is per page on real Windows and the caller is told
		// the first page's. There is no way to read one back out of the tables
		// here, so what it is told is what a freshly allocated page has.
		if (old_protect)
			old_protect.write(page_readwrite);

		try
		{
			space.prot_mem(base, size, prot_from_page(new_protect) | prot_supervisor);
		}
		catch (const std::exception& e)
		{
			THREAD_LOG_WARN("NtProtectVirtualMemory: cannot protect 0x{:X}: {}", base, e.what());
			return STATUS_INVALID_ADDRESS;
		}

		base_address.write(base);
		region_size.write(size);

		THREAD_LOG_INFO("NtProtectVirtualMemory(0x{:X}, {} bytes, protect=0x{:X})",
			base, size, new_protect);

		return STATUS_SUCCESS;
	};

	// Answered by walking the page tables: an address that translates is
	// committed, and one that does not is free. The real one reports the run
	// either state covers, which needs a VAD tree -- so the run here is the one
	// page the caller asked about.
	auto query_vm = [](vcpu& cpu, const std::uint64_t process_handle, const addr_t base_address,
		const std::uint32_t memory_information_class, const addr_t memory_information,
		const std::uint64_t memory_information_length,
		emu_object<std::uint64_t> return_length) -> NTSTATUS
	{
		if (!is_current_process(process_handle))
			return STATUS_INVALID_HANDLE;

		if (memory_information_class != memory_basic_information)
		{
			THREAD_LOG_WARN("NtQueryVirtualMemory: unhandled class {}", memory_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}

		if (return_length)
			return_length.write(sizeof(memory_basic_information_t));

		if (memory_information_length < sizeof(memory_basic_information_t))
			return STATUS_INFO_LENGTH_MISMATCH;

		auto& space = *cpu.curr_addr_space();
		const auto base = mdl_page_base(base_address);
		const bool mapped = space.mmu_->virt_to_phys(space, base).has_value();

		memory_basic_information_t info{};
		info.base_address = base;
		info.allocation_base = mapped ? base : 0;
		info.allocation_protect = mapped ? page_readwrite : 0;
		info.region_size = mdl_page_size;
		info.state = mapped ? mem_state_commit : mem_state_free;
		info.protect = mapped ? page_readwrite : 0;
		info.type = mapped ? mem_type_private : 0;

		emu_object<memory_basic_information_t>(space, memory_information).write(info);

		THREAD_LOG_INFO("NtQueryVirtualMemory(0x{:X}) -> {}", base, mapped ? "committed" : "free");

		return STATUS_SUCCESS;
	};

	// The same section objects MmCreateSection makes, reached by handle rather
	// than by pointer.
	auto create_section = [st](vcpu& cpu, emu_object<std::uint64_t> section_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		emu_object<std::int64_t> maximum_size, const std::uint32_t section_page_protection,
		const std::uint32_t allocation_attributes, const std::uint64_t file_handle) -> NTSTATUS
	{
		if (!section_handle)
			return STATUS_INVALID_PARAMETER;

		auto& space = *cpu.curr_addr_space();

		const emu_object<_UNICODE_STRING> name_obj(space, object_attributes
			? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
			: 0);

		const auto name = narrow_wstring(win::read_unicode_string(name_obj));
		const auto max_size = maximum_size ? maximum_size.read() : 0;

		auto host = std::make_shared<section_host>();
		host->is_image = (allocation_attributes & sec_image) != 0;

		if (file_handle)
		{
			const auto file = st->sys_proc->handle_table().get_object<file_host>(file_handle);

			if (!file)
				return STATUS_INVALID_HANDLE;

			host->file = file->file;
			host->path = file->path;
		}

		if (host->file && host->file->size() == 0)
			return STATUS_MAPPED_FILE_SIZE_ZERO;

		if (!host->file && max_size <= 0)
			return STATUS_INVALID_PARAMETER;

		host->size = host->file
			? static_cast<std::uint64_t>(host->file->size())
			: static_cast<std::uint64_t>(max_size);

		const auto size = static_cast<std::int64_t>(host->size);
		const auto path = host->path;

		std::array<std::uint8_t, section_body_size> body{};
		std::memcpy(body.data() + section_body_size_offset, &size, sizeof(size));

		const auto addr = st->objs.create_object(0, body.data(), body.size(),
			std::move(host), prot_rw | prot_supervisor);

		if (!addr)
			return STATUS_INSUFFICIENT_RESOURCES;

		const auto handle = st->sys_proc->handle_table().create_handle(addr, desired_access);
		section_handle.write(handle);

		THREAD_LOG_INFO("NtCreateSection('{}', file=0x{:X}, max_size={}, protection=0x{:X}, "
			"allocation=0x{:X}) -> handle=0x{:X} ({} bytes)",
			name.empty() ? path : name, file_handle, max_size, section_page_protection,
			allocation_attributes, handle, size);

		return STATUS_SUCCESS;
	};

	// Nothing gives a section a name, so there is no namespace to open one out
	// of -- which is the same answer the real one gives for a name that is not
	// there.
	auto open_section = [](vcpu& cpu, emu_object<std::uint64_t> section_handle,
		const std::uint32_t desired_access,
		emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
	{
		if (section_handle)
			section_handle.write(0);

		auto& space = *cpu.curr_addr_space();

		const emu_object<_UNICODE_STRING> name_obj(space, object_attributes
			? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
			: 0);

		THREAD_LOG_WARN("NtOpenSection('{}', access=0x{:X}): nothing here gives a section a name",
			narrow_wstring(win::read_unicode_string(name_obj)), desired_access);

		return STATUS_OBJECT_NAME_NOT_FOUND;
	};

	auto query_section = [st](vcpu& cpu, const std::uint64_t section_handle,
		const std::uint32_t section_information_class, const addr_t section_information,
		const std::uint64_t section_information_length,
		emu_object<std::uint64_t> return_length) -> NTSTATUS
	{
		const auto host = st->sys_proc->handle_table().get_object<section_host>(section_handle);

		if (!host)
			return STATUS_INVALID_HANDLE;

		if (section_information_class != section_basic_information)
		{
			THREAD_LOG_WARN("NtQuerySection: unhandled class {}", section_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}

		if (return_length)
			return_length.write(sizeof(section_basic_information_t));

		if (section_information_length < sizeof(section_basic_information_t))
			return STATUS_INFO_LENGTH_MISMATCH;

		section_basic_information_t info{};
		info.allocation_attributes = host->is_image ? sec_image : 0;
		info.maximum_size = static_cast<std::int64_t>(host->size);

		emu_object<section_basic_information_t>(*cpu.curr_addr_space(), section_information)
			.write(info);

		THREAD_LOG_INFO("NtQuerySection(0x{:X}, '{}') -> {} bytes",
			section_handle, host->path, host->size);

		return STATUS_SUCCESS;
	};

	// A view is a copy of the section rather than a shared mapping of it, the
	// same way MmMapViewInSystemSpace makes one: nothing here shares pages
	// between a view and the file behind it.
	state.redirect_ntzw(mod, "MapViewOfSection",
		[st](vcpu& cpu, const std::uint64_t section_handle, const std::uint64_t process_handle,
			emu_object<addr_t> base_address, [[maybe_unused]] const std::uint64_t zero_bits,
			[[maybe_unused]] const std::uint64_t commit_size,
			emu_object<std::int64_t> section_offset, emu_object<std::uint64_t> view_size,
			const std::uint32_t inherit_disposition, const std::uint32_t allocation_type,
			const std::uint32_t win32_protect) -> NTSTATUS
		{
			if (!is_current_process(process_handle))
				return STATUS_INVALID_HANDLE;

			const auto host = st->sys_proc->handle_table().get_object<section_host>(section_handle);

			if (!host)
				return STATUS_INVALID_HANDLE;

			const auto offset = section_offset
				? static_cast<std::uint64_t>(section_offset.read()) : 0;

			if (offset >= host->size)
				return STATUS_INVALID_PARAMETER;

			auto size = view_size ? view_size.read() : 0;

			if (!size)
				size = host->size - offset;

			size = std::min<std::uint64_t>(size, host->size - offset);

			auto& space = *cpu.curr_addr_space();
			const auto base = space.alloc(size, prot_from_page(win32_protect) | prot_supervisor);

			if (!base)
				return STATUS_INSUFFICIENT_RESOURCES;

			if (host->file)
			{
				const auto data = host->file->data();
				const auto available = data.size() > offset ? data.size() - offset : 0;
				const auto copied = std::min<std::size_t>(size, available);

				if (copied)
					space.write_mem(base, data.data() + offset, copied);
			}

			if (base_address)
				base_address.write(base);

			if (view_size)
				view_size.write(size);

			st->views[base] = size;

			THREAD_LOG_INFO("NtMapViewOfSection(0x{:X}, '{}', offset={}, inherit={}, "
				"allocation=0x{:X}, protect=0x{:X}) -> 0x{:X}, {} bytes",
				section_handle, host->path, offset, inherit_disposition, allocation_type,
				win32_protect, base, size);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "UnmapViewOfSection",
		[st](vcpu& cpu, const std::uint64_t process_handle, const addr_t base_address) -> NTSTATUS
		{
			if (!is_current_process(process_handle))
				return STATUS_INVALID_HANDLE;

			const auto it = st->views.find(base_address);

			if (it == st->views.end())
			{
				THREAD_LOG_WARN("NtUnmapViewOfSection: 0x{:X} is not a mapped view", base_address);
				return STATUS_INVALID_PARAMETER;
			}

			auto& space = *cpu.curr_addr_space();
			space.mmu_->unmap_virt(space, base_address, it->second);

			THREAD_LOG_INFO("NtUnmapViewOfSection(0x{:X}): {} bytes", base_address, it->second);

			st->views.erase(it);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "AllocateVirtualMemory", allocate_vm);
	state.redirect_ntzw(mod, "AllocateVirtualMemoryEx", allocate_vm_ex);
	state.redirect_ntzw(mod, "FreeVirtualMemory", free_vm);
	state.redirect_ntzw(mod, "ProtectVirtualMemory", protect_vm);
	state.redirect_ntzw(mod, "QueryVirtualMemory", query_vm);
	state.redirect_ntzw(mod, "CreateSection", create_section);
	state.redirect_ntzw(mod, "OpenSection", open_section);
	state.redirect_ntzw(mod, "QuerySection", query_section);
}
