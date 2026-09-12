#pragma once
#include "../../emu/object.hpp"
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
		kpcr_.space()->write_mem<addr_t>(prcb() + offsetof(_KPRCB, CurrentThread), kthread);
	}

	[[nodiscard]] addr_t address() const noexcept { return kpcr_.address(); }
	[[nodiscard]] addr_t prcb() const noexcept { return kpcr_.address() + offsetof(_KPCR, Prcb); }
	[[nodiscard]] addr_space* space() const noexcept { return kpcr_.space(); }

private:
	emu_object<_KPCR> kpcr_;
};
