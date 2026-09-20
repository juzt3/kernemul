#pragma once
#include "../../emu/object.hpp"
#include "../../target.hpp"
#include "../../util/log.hpp"
#include "types.hpp"
#include <format>
#include <vector>


// The version pair says how to read the rest, not which Windows this is.
inline constexpr std::uint16_t pcr_major_version = 1;
inline constexpr std::uint16_t pcr_minor_version = 1;

// The guest divides by these -- KeStallExecutionProcessor scales a spin count -- so not zero.
inline constexpr std::uint32_t default_stall_scale_factor = 1000;
inline constexpr std::uint32_t default_cpu_mhz = 2000;

// Processors are grouped, and a KAFFINITY only ever names one group's worth.
inline constexpr std::uint32_t processor_group_size = 64;

// A count at or above the group size is every bit, because the shift would be undefined.
inline std::uint64_t affinity_mask(const std::size_t count)
{
	return count >= processor_group_size
		? ~std::uint64_t{0}
		: (std::uint64_t{1} << count) - 1;
}

// Nothing here masks interrupts, so an IRQL is a number the guest sets and reads back.
using irql_t = std::uint8_t;

inline constexpr irql_t passive_level  = 0;
inline constexpr irql_t apc_level      = 1;
inline constexpr irql_t dispatch_level = 2;
inline constexpr irql_t ipi_level      = 14;

// x86-64 mirrors it in cr8, which is where __readcr8 and the guest's inlined KeGetCurrentIrql look.
inline constexpr std::size_t kpcr_irql_off =
#if defined(KERNEMUL_ARCH_ARM64)
	offsetof(_KPCR, CurrentIrql);
#else
	offsetof(_KPCR, Irql);
#endif

// One page of queued spin locks, which is what the guest finds through KPCR.LockArray. Only the
// non paged pool entry names a real lock; the rest stay zero, exactly as they were before.
inline constexpr std::size_t lock_array_size = 0x1000;
inline constexpr std::size_t lock_queue_count = lock_array_size / sizeof(_KSPIN_LOCK_QUEUE);

// LockQueueNonPagedPoolLock. The enum it comes from is in no header here, so the index is the
// one that was measured rather than one derived: entry 6, whose Lock sits at 0x68.
inline constexpr std::size_t non_paged_pool_lock_off = 0x68;

inline _KPCR make_default_kpcr(const addr_t kpcr_va, const std::uint32_t number)
{
	_KPCR pcr{};

	pcr.Self = reinterpret_cast<_KPCR*>(static_cast<std::uintptr_t>(kpcr_va));
	pcr.Used_Self = reinterpret_cast<void*>(static_cast<std::uintptr_t>(kpcr_va));
	pcr.MajorVersion = pcr_major_version;
	pcr.MinorVersion = pcr_minor_version;
	pcr.StallScaleFactor = default_stall_scale_factor;

	// The PRCB is embedded rather than separate, but the pointer beside it is what guest code
	// reads to find it. ARM64 has no such field -- PcrReserved0 sits at that offset instead --
	// so there the embedded block is the only way to it.
#if !defined(KERNEMUL_ARCH_ARM64)
	pcr.CurrentPrcb = reinterpret_cast<_KPRCB*>(
		static_cast<std::uintptr_t>(kpcr_va + offsetof(_KPCR, Prcb)));
#endif

	auto& prcb = pcr.Prcb;

	prcb.Number = number;
	prcb.LegacyNumber = static_cast<std::uint8_t>(number);
	prcb.MajorVersion = pcr_major_version;
	prcb.MinorVersion = pcr_minor_version;
	prcb.MHz = default_cpu_mhz;

	prcb.Group = static_cast<std::uint8_t>(number / processor_group_size);
	prcb.GroupIndex = static_cast<std::uint8_t>(number % processor_group_size);
	prcb.GroupSetMember = 1ull << (number % processor_group_size);

	prcb.CoresPerPhysicalProcessor = 1;
	prcb.LogicalProcessorsPerCore = 1;

	return pcr;
}

// Every cpu's block is mapped in the kernel address space rather than being private to the cpu.
class win_per_cpu
{
public:
	win_per_cpu() = default;

	win_per_cpu(addr_space& space, const std::uint32_t number,
		const addr_t non_paged_pool_lock = 0)
		:	number_(number)
	{
		const auto va = space.alloc(sizeof(_KPCR), prot_rw | prot_supervisor);
		kpcr_ = emu_object<_KPCR>(space, va, std::format("KPCR[{}]", number), true);
		kpcr_.write(make_default_kpcr(va, number));

		init_lock_array(space, non_paged_pool_lock);
	}

	void set_current_thread(const addr_t kthread) const
	{
		kpcr_.field(&_KPCR::Prcb).field(&_KPRCB::CurrentThread)
			.write(reinterpret_cast<_KTHREAD*>(static_cast<std::uintptr_t>(kthread)));
	}

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
	// One array per cpu, because a queued lock is acquired through the acquiring cpu's own PCR.
	void init_lock_array(addr_space& space, const addr_t non_paged_pool_lock)
	{
		const auto queues = space.alloc(lock_array_size, prot_rw | prot_supervisor);

		if (!queues)
		{
			LOG_ERR("no room for cpu {}'s lock array, so KPCR.LockArray stays null", number_);
			return;
		}

		// Zeroed first: a queue entry the guest never asked about should read as empty, not as
		// whatever the allocator last left there.
		const std::vector<std::uint8_t> blank(lock_array_size, 0);
		space.write_mem(queues, blank.data(), blank.size());

		// The lock this one entry names lives in ntoskrnl's own data, which is where a driver
		// that asks what module it belongs to expects to be told.
		if (non_paged_pool_lock)
			space.write_mem<addr_t>(queues + non_paged_pool_lock_off, non_paged_pool_lock);
		else
			LOG_WARN("no NonPagedPoolLock, so cpu {}'s lock array names no lock", number_);

		kpcr_.field(&_KPCR::LockArray).write(
			reinterpret_cast<_KSPIN_LOCK_QUEUE*>(static_cast<std::uintptr_t>(queues)));

		// Kept past the constructor so the hook outlives it.
		lock_queues_ = emu_object_arr<_KSPIN_LOCK_QUEUE>(space, queues, lock_queue_count,
			std::format("KPCR[{}].LockArray", number_), true);

		LOG_INFO("cpu {} lock array at 0x{:X}, NonPagedPoolLock 0x{:X} at +0x{:X}",
			number_, queues, non_paged_pool_lock, non_paged_pool_lock_off);
	}

	std::uint32_t number_ = 0;
	emu_object<_KPCR> kpcr_;
	emu_object_arr<_KSPIN_LOCK_QUEUE> lock_queues_;
};
