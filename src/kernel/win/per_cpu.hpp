#pragma once
#include "../../emu/object.hpp"
#include "../../target.hpp"
#include "types.hpp"

// Per-cpu kernel state. Windows keeps one KPCR per processor and reaches it
// through a register the architecture owns -- the GS base on x86-64, TPIDR_EL1
// on ARM64 -- which is why pointing that register at the block is left to the
// arch's emulator. The KPRCB lives inside the KPCR, and its CurrentThread is
// what the guest reads to learn which thread it is running, so the scheduler
// rewrites that one field on every switch.

// What NT stamps into both blocks. The version pair says how to read the rest,
// not which Windows this is.
inline constexpr std::uint16_t pcr_major_version = 1;
inline constexpr std::uint16_t pcr_minor_version = 1;

// Nothing in the emulator keeps time from these, but the guest divides by
// them -- KeStallExecutionProcessor scales a spin count by StallScaleFactor --
// so they have to be plausible rather than zero.
inline constexpr std::uint32_t default_stall_scale_factor = 1000;
inline constexpr std::uint32_t default_cpu_mhz = 2000;

// Processors are grouped, and a KAFFINITY only ever names one group's worth.
inline constexpr std::uint32_t processor_group_size = 64;

// The interrupt request levels a driver names. Nothing here masks interrupts --
// there are none to mask -- so an IRQL is a number the guest sets and reads
// back, and the levels matter only because the guest compares against them.
using irql_t = std::uint8_t;

inline constexpr irql_t passive_level  = 0;
inline constexpr irql_t apc_level      = 1;
inline constexpr irql_t dispatch_level = 2;

// NT keeps the current IRQL in the KPCR, under a different name on each
// architecture. x86-64 also mirrors it in cr8, which is where __readcr8 and the
// guest's own inlined KeGetCurrentIrql look -- see x86_win_emulator.
inline constexpr std::size_t kpcr_irql_off =
#if defined(KERNEMUL_ARCH_ARM64)
	offsetof(_KPCR, CurrentIrql);
#else
	offsetof(_KPCR, Irql);
#endif

inline _KPCR make_default_kpcr(const addr_t kpcr_va, const std::uint32_t number)
{
	_KPCR pcr{};

	// A KPCR is found by a register, so the guest needs its address from the
	// inside to hand it on or to compare two cpus.
	pcr.Self = reinterpret_cast<_KPCR*>(static_cast<std::uintptr_t>(kpcr_va));
	pcr.Used_Self = reinterpret_cast<void*>(static_cast<std::uintptr_t>(kpcr_va));
	pcr.MajorVersion = pcr_major_version;
	pcr.MinorVersion = pcr_minor_version;
	pcr.StallScaleFactor = default_stall_scale_factor;

	auto& prcb = pcr.Prcb;

	prcb.Number = number;
	prcb.LegacyNumber = static_cast<std::uint8_t>(number);
	prcb.MajorVersion = pcr_major_version;
	prcb.MinorVersion = pcr_minor_version;
	prcb.MHz = default_cpu_mhz;

	// A group holds up to 64 processors and an affinity mask covers one group,
	// so the cpu's bit is its number within its own group.
	prcb.Group = static_cast<std::uint8_t>(number / processor_group_size);
	prcb.GroupIndex = static_cast<std::uint8_t>(number % processor_group_size);
	prcb.GroupSetMember = 1ull << (number % processor_group_size);

	prcb.CoresPerPhysicalProcessor = 1;
	prcb.LogicalProcessorsPerCore = 1;

	return pcr;
}

// One cpu's KPCR, in kernel memory. Every cpu's block is mapped in the kernel
// address space rather than being private to the cpu, which is how the guest
// reaches another processor's KPRCB.
class win_per_cpu
{
public:
	win_per_cpu() = default;

	win_per_cpu(addr_space& space, const std::uint32_t number)
	{
		const auto va = space.alloc(sizeof(_KPCR), prot_rw | prot_supervisor);
		kpcr_ = emu_object<_KPCR>(space, va);
		kpcr_.write(make_default_kpcr(va, number));
	}

	// Written on every context switch, so it puts down the one pointer instead
	// of the whole block: the guest owns this memory too, and everything else
	// in it is the cpu's, not the thread's.
	void set_current_thread(const addr_t kthread) const
	{
		kpcr_.field(&_KPCR::Prcb).field(&_KPRCB::CurrentThread)
			.write(reinterpret_cast<_KTHREAD*>(static_cast<std::uintptr_t>(kthread)));
	}

	// The guest's own view of this cpu's IRQL. A driver reads it straight out
	// of the block as often as it calls KeGetCurrentIrql, so the block is where
	// it is kept rather than beside it on the host.
	void set_irql(const irql_t irql) const
	{
		kpcr_.field_at<irql_t>(kpcr_irql_off).write(irql);
	}

	[[nodiscard]] irql_t irql() const
	{
		return kpcr_.field_at<irql_t>(kpcr_irql_off).read();
	}

	[[nodiscard]] const emu_object<_KPCR>& object() const noexcept { return kpcr_; }
	[[nodiscard]] addr_t address() const noexcept { return kpcr_.address(); }
	[[nodiscard]] addr_t prcb() const noexcept { return kpcr_.address() + offsetof(_KPCR, Prcb); }
	[[nodiscard]] addr_space* space() const noexcept { return kpcr_.space(); }

private:
	emu_object<_KPCR> kpcr_;
};
