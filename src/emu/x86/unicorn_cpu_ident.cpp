#include "../../target.hpp"

#if !defined(KERNEMUL_ARCH_ARM64)

#include "unicorn_cpu_ident.hpp"

#include "arch.hpp"
#include "unicorn.hpp"
#include "../../util/log.hpp"

#include <chrono>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <unordered_set>

namespace ia32 {
#include <ia32.hpp>
}

namespace x86
{

namespace
{

struct msr_range
{
	std::uint32_t first;
	std::uint32_t last;
};

template <std::size_t N>
constexpr bool in(const msr_range (&ranges)[N], const std::uint32_t id)
{
	for (const auto& [first, last] : ranges)
	{
		if (id >= first && id <= last)
			return true;
	}

	return false;
}

// The tsc runs at 78 ticks of the crystal, which is the base clock leaf 0x16 reports.
constexpr std::uint32_t base_mhz   = 3000;
constexpr std::uint32_t max_mhz    = 5800;
constexpr std::uint32_t bus_mhz    = 100;
constexpr std::uint32_t crystal_hz = 38'400'000;
constexpr std::uint32_t tsc_numerator   = 156;
constexpr std::uint32_t tsc_denominator = 2;

// Leaf 6 decides whether vgk.sys runs at all; Unicorn answers it with ARAT alone, which is no
// shipped part. Thermal sensor, turbo, arat, power limit, clock modulation, package thermal;
// then mperf/aperf and the energy bias register.
constexpr std::uint32_t thermal_eax = 0x77;
constexpr std::uint32_t thermal_ebx = 2;
constexpr std::uint32_t thermal_ecx = 9;

constexpr std::uint32_t addr_width_leaf = 0x80000008;

// 48 linear bits, 46 physical -- what the part this model names actually reports.
constexpr std::uint32_t addr_width_eax = (48u << 8) | 46u;

constexpr std::uint32_t thermal_leaf   = 0x6;
constexpr std::uint32_t tsc_ratio_leaf = 0x15;
constexpr std::uint32_t frequency_leaf = 0x16;

// Unicorn sets leaf 1's hypervisor bit for every model, so something has to answer the range it
// promises.
constexpr std::uint32_t hv_leaf_first   = 0x40000000;
constexpr std::uint32_t hv_leaf_last    = 0x4FFFFFFF;
constexpr std::uint32_t hv_leaf_max     = 0x40000006;
constexpr std::uint32_t hv_interface_id = 0x31237648;  // "Hv#1"

constexpr std::uint32_t hv_msr_first       = 0x40000000;
constexpr std::uint32_t hv_msr_last        = 0x400000FF;
constexpr std::uint32_t hv_msr_guest_os_id = 0x40000000;
constexpr std::uint32_t hv_msr_hypercall   = 0x40000001;
constexpr std::uint32_t hv_msr_vp_index    = 0x40000002;
constexpr std::uint32_t hv_msr_time_ref    = 0x40000020;

constexpr std::uint64_t apic_base = 0xFEE00000 | (1ull << 11);
constexpr std::uint64_t apic_bsp  = 1ull << 8;

constexpr std::uint32_t msr_debugctl = 0x1D9;
constexpr std::uint32_t msr_mperf    = 0xE7;
constexpr std::uint32_t msr_aperf    = 0xE8;

// LBR, BTF, TR, BTS, BTINT, BTS_OFF_OS/USR, the freeze bits, uncore pmi, smm, rtm debug. A
// write that sets anything else faults on hardware.
constexpr std::uint64_t debugctl_implemented = 0xFFC3;

// Read-only, and zero when VMX is not exposed. The second is AMD's VM_CR.
constexpr msr_range vmx[] = {
	{ IA32_VMX_BASIC, IA32_VMX_VMFUNC },
	{ 0xC0010114, 0xC0010114 },
};

constexpr msr_range pt[] = {
	{ 0x560, 0x561 },
	{ 0x570, 0x572 },
	{ 0x580, 0x58F },
};

// The msr space this cpu has. Anything in here reads zero; anything outside faults, as a real
// cpu does. Answering every address at once is how a guest tells which hypervisor it is under:
// KVM sits at 0x4B564D00, Hyper-V at 0x40000000, VMware and Xen elsewhere, and it reads each
// behind an exception handler to see which answer.
constexpr msr_range implemented[] = {
	{ hv_msr_first, hv_msr_last },
	{ 0x17, 0x17 }, { 0x34, 0x35 }, { 0x3B, 0x3B }, { 0x48, 0x4F },
	{ 0x8B, 0x8B }, { 0xCE, 0xCE }, { 0xE2, 0xE2 }, { 0xFE, 0xFE },
	{ msr_mperf, msr_aperf },
	{ 0x10A, 0x10B }, { 0x122, 0x123 }, { 0x17D, 0x17D },
	{ 0x198, 0x19C }, { 0x1A0, 0x1A2 }, { 0x1B0, 0x1B1 },
	{ msr_debugctl, msr_debugctl }, { 0x1F2, 0x1F3 },
	{ 0x280, 0x2FF }, { 0x345, 0x345 }, { 0x38D, 0x391 }, { 0x3F1, 0x3F7 },
	{ 0x6E0, 0x6E1 }, { 0xC80, 0xC82 }, { 0xC0000103, 0xC0000104 },
};

template <typename Ratio>
std::uint64_t elapsed()
{
	using ticks = std::chrono::duration<std::int64_t, Ratio>;

	const auto since_start = std::chrono::steady_clock::now().time_since_epoch();
	return static_cast<std::uint64_t>(std::chrono::duration_cast<ticks>(since_start).count());
}

std::uint32_t reg32(vcpu& cpu, const reg_t r)
{
	return static_cast<std::uint32_t>(cpu.reg<std::uint64_t>(r));
}

class cpu_identity
{
public:
	cpu_identity()
	{
		// Locked, with the bit that would enable VMX outside SMX clear.
		msrs_[IA32_FEATURE_CONTROL] = 1;

		// The guest's to fill in, seeded so its writes stick.
		msrs_[hv_msr_guest_os_id] = 0;
		msrs_[hv_msr_hypercall] = 0;
	}

	bool on_cpuid(vcpu& cpu);
	bool on_rdmsr(vcpu& cpu);
	bool on_wrmsr(vcpu& cpu);

private:
	[[nodiscard]] std::optional<std::uint64_t> read(vcpu& cpu, std::uint32_t id);
	[[nodiscard]] bool write(vcpu& cpu, std::uint32_t id, std::uint64_t value);

	// Shared registers key on the id alone; per cpu ones carry the cpu in the high half.
	static std::uint64_t key(const vcpu& cpu, const std::uint32_t id)
	{
		if (id != msr_debugctl)
			return id;

		return (static_cast<std::uint64_t>(cpu.id()) << 32) | id;
	}

	// Leaves only: a driver asks for the same handful thousands of times. Every msr access is
	// logged, because which register is touched how often is the interesting part there.
	bool first_leaf(const std::uint32_t leaf)
	{
		std::scoped_lock lock(mtx_);
		return seen_leaves_.insert(leaf).second;
	}

	std::mutex mtx_;
	std::unordered_map<std::uint64_t, std::uint64_t> msrs_;
	std::unordered_set<std::uint32_t> seen_leaves_;
};

bool cpu_identity::on_cpuid(vcpu& cpu)
{
	const auto leaf = reg32(cpu, x86::rax);

	if (first_leaf(leaf))
		LOG_INFO("cpu {}: cpuid leaf 0x{:X}, subleaf 0x{:X}",
			cpu.id(), leaf, reg32(cpu, x86::rcx));

	// The model this emulator names is a 13900K, and that part is answered by the cpu model.
	// The address width is not: tcg reports 40 physical bits for every model, where the part
	// it claims to be has 46. A guest that reads the brand and then the width sees a cpu that
	// does not exist -- and the width is also what a page table walker masks a pfn with.
	if (leaf == addr_width_leaf)
	{
		cpu.reg(x86::rax, static_cast<std::uint64_t>(addr_width_eax));
		cpu.reg(x86::rbx, std::uint64_t{ 0 });
		cpu.reg(x86::rcx, std::uint64_t{ 0 });
		cpu.reg(x86::rdx, std::uint64_t{ 0 });

		return true;
	}

	const bool model_leaf = leaf == thermal_leaf || leaf == tsc_ratio_leaf
		|| leaf == frequency_leaf;

	if (!model_leaf && (leaf < hv_leaf_first || leaf > hv_leaf_last))
		return false;

	std::uint32_t out[4]{};

	switch (leaf)
	{
	case thermal_leaf:
		out[0] = thermal_eax;
		out[1] = thermal_ebx;
		out[2] = thermal_ecx;
		break;

	case tsc_ratio_leaf:
		out[0] = tsc_denominator;
		out[1] = tsc_numerator;
		out[2] = crystal_hz;
		break;

	case frequency_leaf:
		out[0] = base_mhz;
		out[1] = max_mhz;
		out[2] = bus_mhz;
		break;

	case hv_leaf_first:
		out[0] = hv_leaf_max;
		std::memcpy(&out[1], "Microsoft Hv", 12);
		break;

	case hv_leaf_first + 1:
		out[0] = hv_interface_id;
		break;

	// Version, feature and recommendation data for services nothing here offers.
	default:
		break;
	}

	cpu.reg(x86::rax, static_cast<std::uint64_t>(out[0]));
	cpu.reg(x86::rbx, static_cast<std::uint64_t>(out[1]));
	cpu.reg(x86::rcx, static_cast<std::uint64_t>(out[2]));
	cpu.reg(x86::rdx, static_cast<std::uint64_t>(out[3]));

	return true;
}

std::optional<std::uint64_t> cpu_identity::read(vcpu& cpu, const std::uint32_t id)
{
	if (id == hv_msr_vp_index)
		return cpu.id();

	if (id == hv_msr_time_ref)
		return elapsed<std::ratio<1, 10'000'000>>();

	// Leaf 6 promises these, and a guest divides one delta by the other to find its clock, so
	// they have to run and run together.
	if (id == msr_mperf || id == msr_aperf)
		return elapsed<std::ratio<1, static_cast<std::intmax_t>(base_mhz) * 1'000'000>>();

	if (in(vmx, id))
		return 0;

	if (in(pt, id))
	{
		LOG_ERR("processor trace msr 0x{:X} read: answered 0, but a guest that gets this far "
			"is looking for a trace it can turn on and watch this emulator with", id);

		return 0;
	}

	if (id == IA32_APIC_BASE)
		return apic_base | (cpu.id() == 0 ? apic_bsp : 0);

	{
		std::scoped_lock lock(mtx_);

		if (const auto it = msrs_.find(key(cpu, id)); it != msrs_.end())
			return it->second;
	}

	// Zero keeps it a register that is there; nullopt hands it to the cpu, which faults.
	if (in(implemented, id))
		return 0;

	return std::nullopt;
}

bool cpu_identity::on_rdmsr(vcpu& cpu)
{
	const auto id = reg32(cpu, x86::rcx);
	const auto value = read(cpu, id);

	if (value)
	{
		LOG_INFO("cpu {}: rdmsr 0x{:X} -> 0x{:X}", cpu.id(), id, *value);
	}
	else
	{
		// Declining hands it to the cpu, which faults on everything it does not model itself.
		// A guest probing for a hypervisor's registers is looking for exactly this, so it is
		// worth seeing every time rather than once.
		LOG_WARN("cpu {}: rdmsr 0x{:X}: not in this cpu's msr space, so the cpu answers it. "
			"#GP unless it models the register", cpu.id(), id);

		return false;
	}

	cpu.reg(x86::rax, *value & 0xFFFFFFFF);
	cpu.reg(x86::rdx, *value >> 32);

	return true;
}

bool cpu_identity::write(vcpu& cpu, const std::uint32_t id, const std::uint64_t value)
{
	// No cpu forgets what was written here, and a reserved bit faults rather than sticking.
	if (id == msr_debugctl)
	{
		if (value & ~debugctl_implemented)
		{
			LOG_WARN("write of 0x{:X} to IA32_DEBUGCTL sets reserved bits 0x{:X}: faulting, "
				"as the cpu does", value, value & ~debugctl_implemented);

			return false;
		}

		std::scoped_lock lock(mtx_);
		msrs_[key(cpu, id)] = value;

		return true;
	}

	// Read-only on hardware, so dropping is closer than letting the guest install an answer.
	if (in(vmx, id))
	{
		LOG_WARN("write of 0x{:X} to read-only vmx msr 0x{:X} dropped", value, id);
		return true;
	}

	if (in(pt, id))
	{
		LOG_ERR("processor trace msr 0x{:X} written 0x{:X}: dropped, so it keeps reading 0",
			id, value);

		return true;
	}

	// The lock bit is one-way, and bit 2 would let the guest turn VMX on.
	if (id == IA32_FEATURE_CONTROL)
	{
		constexpr std::uint64_t enable_vmx_outside_smx = 1ull << 2;

		std::scoped_lock lock(mtx_);
		msrs_[IA32_FEATURE_CONTROL] = (value | 1) & ~enable_vmx_outside_smx;

		return true;
	}

	{
		std::scoped_lock lock(mtx_);

		if (const auto it = msrs_.find(key(cpu, id)); it != msrs_.end())
		{
			it->second = value;
			return true;
		}
	}

	// Writable because it exists, dropped because nothing here uses it.
	return in(implemented, id);
}

bool cpu_identity::on_wrmsr(vcpu& cpu)
{
	const auto id = reg32(cpu, x86::rcx);
	const auto value = (static_cast<std::uint64_t>(reg32(cpu, x86::rdx)) << 32)
		| reg32(cpu, x86::rax);

	const auto taken = write(cpu, id, value);

	if (taken)
		LOG_INFO("cpu {}: wrmsr 0x{:X} <- 0x{:X}", cpu.id(), id, value);
	else
		LOG_WARN("cpu {}: wrmsr 0x{:X} <- 0x{:X}: declined, so the cpu answers it. #GP unless "
			"it models the register", cpu.id(), id, value);

	return taken;
}

}

void install_cpu_identity(x86_unicorn_emu& emu)
{
	constexpr addr_t everywhere = std::numeric_limits<addr_t>::max();

	// Owned by the hooks, so it lives exactly as long as they do.
	auto state = std::make_shared<cpu_identity>();

	emu.hook_insn(0, everywhere, hook_insn_t::cpuid,
		[state](vcpu& cpu) { return state->on_cpuid(cpu); });

	emu.hook_insn(0, everywhere, hook_insn_t::rdmsr,
		[state](vcpu& cpu) { return state->on_rdmsr(cpu); });

	emu.hook_insn(0, everywhere, hook_insn_t::wrmsr,
		[state](vcpu& cpu) { return state->on_wrmsr(cpu); });
}

}

#endif
