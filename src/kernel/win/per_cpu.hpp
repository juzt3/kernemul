#pragma once
#include "../../emu/object.hpp"
#include "../../target.hpp"
#include "../../util/log.hpp"
#include "types.hpp"
#include <format>


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

// x86-64 mirrors it in cr8, which is where __readcr8 and the guest's inlined KeGetCurrentIrql look.
inline constexpr std::size_t kpcr_irql_off =
#if defined(KERNEMUL_ARCH_ARM64)
	offsetof(_KPCR, CurrentIrql);
#else
	offsetof(_KPCR, Irql);
#endif

// A queued spin lock is {Next, Lock}, and the guest indexes the array by a
// _KSPIN_LOCK_QUEUE_NUMBER -- an enum that is in no header here and whose values move between
// builds. So rather than guess which index means which lock, every entry is given its own
// backing word: whichever one the guest picks, it finds a valid pointer to distinct storage.
inline constexpr std::size_t lock_queue_count = 33;

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

	win_per_cpu(addr_space& space, const std::uint32_t number)
		:	number_(number)
	{
		const auto va = space.alloc(sizeof(_KPCR), prot_rw | prot_supervisor);
		kpcr_ = emu_object<_KPCR>(space, va, std::format("KPCR[{}]", number), true);
		kpcr_.write(make_default_kpcr(va, number));

		// DIAGNOSTIC: temporarily disabled
		// init_lock_array(space);
		(void)space;
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
	void init_lock_array(addr_space& space)
	{
		constexpr auto queues_size = lock_queue_count * sizeof(_KSPIN_LOCK_QUEUE);
		constexpr auto locks_size = lock_queue_count * sizeof(std::uint64_t);

		const auto queues = space.alloc(queues_size + locks_size, prot_rw | prot_supervisor);

		if (!queues)
		{
			LOG_ERR("no room for cpu {}'s lock array; KPCR.LockArray stays null",
				kpcr_.field(&_KPCR::Prcb).field(&_KPRCB::Number).read());
			return;
		}

		// The backing words live past the queues in the same allocation: one page either way,
		// and nothing else has to know where they are.
		const auto locks = queues + queues_size;

		for (std::size_t i = 0; i < lock_queue_count; ++i)
		{
			_KSPIN_LOCK_QUEUE entry{};
			entry.Lock = reinterpret_cast<unsigned __int64*>(
				static_cast<std::uintptr_t>(locks + i * sizeof(std::uint64_t)));

			space.write_mem(queues + i * sizeof(_KSPIN_LOCK_QUEUE), entry);
			space.write_mem<std::uint64_t>(locks + i * sizeof(std::uint64_t), 0);
		}

		kpcr_.field(&_KPCR::LockArray).write(
			reinterpret_cast<_KSPIN_LOCK_QUEUE*>(static_cast<std::uintptr_t>(queues)));

		// Kept past the constructor so the hooks outlive it: a queued lock the guest reaches
		// through the PCR is one of the few places it touches state nothing here ever runs.
		lock_queues_ = emu_object_arr<_KSPIN_LOCK_QUEUE>(space, queues, lock_queue_count,
			std::format("KPCR.LockArray[{}]", number_), true);

		lock_words_ = emu_object_arr<std::uint64_t>(space, locks, lock_queue_count,
			std::format("KPCR.LockArray.Lock[{}]", number_), true);
	}

	std::uint32_t number_ = 0;
	emu_object<_KPCR> kpcr_;
	emu_object_arr<_KSPIN_LOCK_QUEUE> lock_queues_;
	emu_object_arr<std::uint64_t> lock_words_;
};
