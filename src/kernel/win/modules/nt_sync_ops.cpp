#include "nt_sync_ops.hpp"
#include "../win_kernel.hpp"
#include "../dispatcher.hpp"
#include "../thread.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"

namespace
{

// FM_LOCK_BIT. A fast mutex is free while bit 0 of Count is set; acquiring
// clears it, and the bits above it count the waiters that queue on the event.
constexpr std::int32_t fm_lock_bit = 1;

std::int32_t mutex_count(const emu_object<_FAST_MUTEX>& mutex)
{
	return static_cast<std::int32_t>(mutex.field(&_FAST_MUTEX::Count).read());
}

// Take the lock bit if it is there. Nothing can contend a fast mutex here for
// the same reason nothing contends a spin lock -- the acquiring cpu is stopped
// inside the handler -- so a mutex found already held means the guest reached
// it down a path the missing KeWaitForSingleObject would have blocked.
void take_mutex(const emu_object<_FAST_MUTEX>& mutex, const char* who)
{
	const auto count = mutex_count(mutex);

	if (!(count & fm_lock_bit))
	{
		auto contention = mutex.field(&_FAST_MUTEX::Contention);
		contention.write(contention.read() + 1);

		THREAD_LOG_ERR("{}: 0x{:X} is already held and nothing here can wait",
			who, mutex.address());

		return;
	}

	mutex.field(&_FAST_MUTEX::Count).write(count & ~fm_lock_bit);
}

void own_mutex(const emu_object<_FAST_MUTEX>& mutex, vcpu& cpu)
{
	const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());
	const auto owner = (t && t->ethread()) ? t->ethread().address() : 0;

	mutex.field(&_FAST_MUTEX::Owner).write(guest_ptr<void>(owner));
}

// Put the lock bit back. Nothing ever queues behind the mutex, but the guest
// owns Count and a release of one that was never taken is a driver bug worth
// the same report the dispatcher objects give it.
void give_mutex(const emu_object<_FAST_MUTEX>& mutex, const char* who)
{
	const auto count = mutex_count(mutex);

	mutex.field(&_FAST_MUTEX::Owner).write(nullptr);

	if (count & fm_lock_bit)
	{
		THREAD_LOG_ERR("{}: 0x{:X} was not held", who, mutex.address());
		return;
	}

	mutex.field(&_FAST_MUTEX::Count).write(count | fm_lock_bit);
}

// The fast mutex and the guarded mutex. They are one lock on this kernel: the
// linker folds ExAcquireFastMutex onto KeAcquireGuardedMutex on both
// architectures, and ExReleaseFastMutex onto KeReleaseGuardedMutex on x86-64,
// so one handler serves both names whether or not it wants to. What is left of
// the distinction is that a guarded mutex holds APCs off with a region counter
// rather than by raising IRQL, and nothing here delivers an APC either way.
void register_fast_mutexes(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "KeInitializeGuardedMutex",
		[](vcpu&, emu_object<_FAST_MUTEX> mutex)
		{
			if (!mutex)
				return;

			mutex.field(&_FAST_MUTEX::Count).write(fm_lock_bit);
			mutex.field(&_FAST_MUTEX::Owner).write(nullptr);
			mutex.field(&_FAST_MUTEX::Contention).write(0);

			win::init_dispatcher(mutex.field(&_FAST_MUTEX::Event),
				win::event_synchronization_object, 0);

			THREAD_LOG_INFO("KeInitializeGuardedMutex(mutex=0x{:X})", mutex.address());
		});

	// The IRQL the caller was at is kept in the mutex, because the release is
	// what puts it back and the release is not handed it.
	auto acquire = [st](vcpu& cpu, emu_object<_FAST_MUTEX> mutex)
	{
		if (!mutex)
			return;

		auto* emulator = st->emulator();
		const auto old_irql = emulator ? emulator->set_irql(cpu, apc_level) : passive_level;

		take_mutex(mutex, "ExAcquireFastMutex");
		own_mutex(mutex, cpu);
		mutex.field(&_FAST_MUTEX::OldIrql).write(old_irql);

		THREAD_LOG_INFO("ExAcquireFastMutex(mutex=0x{:X}): old irql {}",
			mutex.address(), old_irql);
	};

	auto release = [st](vcpu& cpu, emu_object<_FAST_MUTEX> mutex)
	{
		if (!mutex)
			return;

		const auto old_irql = static_cast<irql_t>(
			mutex.field(&_FAST_MUTEX::OldIrql).read());

		give_mutex(mutex, "ExReleaseFastMutex");

		if (auto* emulator = st->emulator())
			emulator->set_irql(cpu, old_irql);

		THREAD_LOG_INFO("ExReleaseFastMutex(mutex=0x{:X}): irql back to {}",
			mutex.address(), old_irql);
	};

	auto try_acquire = [st](vcpu& cpu, emu_object<_FAST_MUTEX> mutex) -> bool
	{
		if (!mutex)
			return false;

		auto* emulator = st->emulator();
		const auto old_irql = emulator ? emulator->set_irql(cpu, apc_level) : passive_level;
		const auto count = mutex_count(mutex);

		if (!(count & fm_lock_bit))
		{
			if (emulator)
				emulator->set_irql(cpu, old_irql);

			THREAD_LOG_INFO("ExTryToAcquireFastMutex(mutex=0x{:X}) -> false", mutex.address());

			return false;
		}

		mutex.field(&_FAST_MUTEX::Count).write(count & ~fm_lock_bit);
		own_mutex(mutex, cpu);
		mutex.field(&_FAST_MUTEX::OldIrql).write(old_irql);

		THREAD_LOG_INFO("ExTryToAcquireFastMutex(mutex=0x{:X}) -> true, old irql {}",
			mutex.address(), old_irql);

		return true;
	};

	state.redirect(mod, "ExAcquireFastMutex", acquire);
	state.redirect(mod, "KeAcquireGuardedMutex", acquire);
	state.redirect(mod, "ExReleaseFastMutex", release);
	state.redirect(mod, "KeReleaseGuardedMutex", release);
	state.redirect(mod, "ExTryToAcquireFastMutex", try_acquire);
	state.redirect(mod, "KeTryToAcquireGuardedMutex", try_acquire);

	// The unsafe pair leave the IRQL alone: the caller is already holding APCs
	// off, by a critical region or by having raised the level itself.
	state.redirect(mod, "ExAcquireFastMutexUnsafe",
		[](vcpu& cpu, emu_object<_FAST_MUTEX> mutex)
		{
			if (!mutex)
				return;

			take_mutex(mutex, "ExAcquireFastMutexUnsafe");
			own_mutex(mutex, cpu);

			THREAD_LOG_INFO("ExAcquireFastMutexUnsafe(mutex=0x{:X})", mutex.address());
		});

	state.redirect(mod, "ExReleaseFastMutexUnsafe",
		[](vcpu&, emu_object<_FAST_MUTEX> mutex)
		{
			if (!mutex)
				return;

			give_mutex(mutex, "ExReleaseFastMutexUnsafe");

			THREAD_LOG_INFO("ExReleaseFastMutexUnsafe(mutex=0x{:X})", mutex.address());
		});
}

}

// None of these can block. A wait is only a wait if something else could have
// run in the meantime, and the object a driver signals here is one it built in
// its own memory, which nothing else in the emulator holds a reference to --
// there is no second party to wake. What is left, and what the guest reads
// back, is the signal state in the object's own header, so that is what these
// keep exactly right.
//
// KeWaitForSingleObject is deliberately not implemented. That is what keeps the
// omission honest: a driver that waits is told so at the point it waits, rather
// than sailing past a wait that silently succeeded.
void modules::register_ntoskrnl_sync_ops(win_kernel_state& state, proc_module& mod)
{
	state.redirect(mod, "KeInitializeEvent",
		[](vcpu&, emu_object<_KEVENT> event, const std::uint32_t type,
			const std::uint8_t state)
		{
			if (!event)
				return;

			win::init_dispatcher(event,
				type == 0 ? win::event_notification_object : win::event_synchronization_object,
				state ? 1 : 0);

			THREAD_LOG_INFO("KeInitializeEvent(event=0x{:X}, type={}, state={})",
				event.address(), type == 0 ? "notification" : "synchronization", state);
		});

	state.redirect(mod, "KeSetEvent",
		[](vcpu&, emu_object<_KEVENT> event, const std::int32_t increment,
			const std::uint8_t wait) -> std::int32_t
		{
			if (!event)
				return 0;

			const auto previous = win::signal_state(event);
			win::set_signal_state(event, 1);

			THREAD_LOG_INFO("KeSetEvent(event=0x{:X}, increment={}, wait={}) -> {}",
				event.address(), increment, wait, previous);

			return previous;
		});

	// KeClearEvent is KeResetEvent without the return value, and the two are so
	// nearly identical that the linker folds them: both exports name one
	// address, on x64 and ARM64 alike. Registering a second handler would
	// silently replace the first, and nothing at run time can tell which name
	// the caller used, so one handler serves both. It returns the previous
	// state; a caller that meant KeClearEvent ignores that, exactly as on real
	// Windows and for the same reason.
	auto reset_event = [](vcpu&, emu_object<_KEVENT> event) -> std::int32_t
	{
		if (!event)
			return 0;

		const auto previous = win::signal_state(event);
		win::set_signal_state(event, 0);

		THREAD_LOG_INFO("KeResetEvent(event=0x{:X}) -> {}", event.address(), previous);

		return previous;
	};

	state.redirect(mod, "KeResetEvent", reset_event);
	state.redirect(mod, "KeClearEvent", reset_event);

	state.redirect(mod, "KeInitializeMutex",
		[](vcpu&, emu_object<_KMUTANT> mutex, const std::uint32_t level)
		{
			if (!mutex)
				return;

			win::init_dispatcher(mutex, win::mutant_object, 1);

			mutex.field(&_KMUTANT::MutantListEntry).write(guest_links(0, 0));
			mutex.field(&_KMUTANT::OwnerThread).write(nullptr);
			mutex.field(&_KMUTANT::MutantFlags).write(0);
			mutex.field(&_KMUTANT::ApcDisable).write(1);

			THREAD_LOG_INFO("KeInitializeMutex(mutex=0x{:X}, level={})",
				mutex.address(), level);
		});

	// Nothing here acquires a mutex -- that is KeWaitForSingleObject's job --
	// so every release is of one that was already free. Real Windows bugchecks
	// on that, so it is reported rather than quietly counted: a driver reaching
	// it is relying on a wait that did not happen.
	state.redirect(mod, "KeReleaseMutex",
		[](vcpu&, emu_object<_KMUTANT> mutex, const std::uint8_t wait) -> std::int32_t
		{
			if (!mutex)
				return 0;

			const auto previous = win::signal_state(mutex);

			if (previous > 0)
				THREAD_LOG_WARN("KeReleaseMutex: mutex 0x{:X} was not held (state={})",
					mutex.address(), previous);

			win::set_signal_state(mutex, previous + 1);
			mutex.field(&_KMUTANT::OwnerThread).write(nullptr);

			THREAD_LOG_INFO("KeReleaseMutex(mutex=0x{:X}, wait={}) -> {}",
				mutex.address(), wait, previous);

			return previous;
		});

	state.redirect(mod, "KeInitializeSemaphore",
		[](vcpu&, emu_object<_KSEMAPHORE> semaphore, const std::int32_t count,
			const std::int32_t limit)
		{
			if (!semaphore)
				return;

			win::init_dispatcher(semaphore, win::semaphore_object, count);
			semaphore.field(&_KSEMAPHORE::Limit).write(limit);

			THREAD_LOG_INFO("KeInitializeSemaphore(semaphore=0x{:X}, count={}, limit={})",
				semaphore.address(), count, limit);
		});

	// Going past the limit raises STATUS_SEMAPHORE_LIMIT_EXCEEDED on real
	// Windows and leaves the count alone. The count is left alone here too --
	// what is missing is the raise, so this is reported as an error rather than
	// pushed somewhere the guest can never bring it back from.
	state.redirect(mod, "KeReleaseSemaphore",
		[](vcpu&, emu_object<_KSEMAPHORE> semaphore, const std::int32_t increment,
			const std::int32_t adjustment, const std::uint8_t wait) -> std::int32_t
		{
			if (!semaphore)
				return 0;

			const auto previous = win::signal_state(semaphore);
			const auto limit = static_cast<std::int32_t>(
				semaphore.field(&_KSEMAPHORE::Limit).read());

			if (previous + adjustment > limit)
			{
				THREAD_LOG_ERR("KeReleaseSemaphore: 0x{:X} count {} + {} exceeds limit {}",
					semaphore.address(), previous, adjustment, limit);
				return previous;
			}

			win::set_signal_state(semaphore, previous + adjustment);

			THREAD_LOG_INFO(
				"KeReleaseSemaphore(semaphore=0x{:X}, increment={}, adjustment={}, wait={}) -> {}",
				semaphore.address(), increment, adjustment, wait, previous);

			return previous;
		});

	// Nothing here delivers an APC, so the count is only ever read back -- but
	// the guest does read it, and a driver that leaves without entering has
	// corrupted a count Windows checks on the way out of a system call.
	auto apc_disable = [](vcpu& cpu, const std::int32_t delta) -> std::int32_t
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t || !t->ethread())
			return 0;

		auto count = t->kernel_apc_disable();
		const auto updated = static_cast<std::int32_t>(count.read() + delta);

		count.write(static_cast<std::int16_t>(updated));

		return updated;
	};

	// An interlocked singly-linked list head. Nothing pushes or pops one yet --
	// those are the Ex*SList routines -- but a driver initialises it up front
	// and the guest reads the head back, so an uninitialised one is a list that
	// looks like it already has entries.
	state.redirect(mod, "InitializeSListHead",
		[](vcpu&, emu_object<_SLIST_HEADER> slist_head)
		{
			if (!slist_head)
				return;

			slist_head.write(_SLIST_HEADER{});

			THREAD_LOG_INFO("InitializeSListHead(0x{:X})", slist_head.address());
		});

	state.redirect(mod, "KeEnterCriticalRegion", [apc_disable](vcpu& cpu)
	{
		THREAD_LOG_INFO("KeEnterCriticalRegion: apc disable count now {}",
			apc_disable(cpu, -1));
	});

	state.redirect(mod, "KeLeaveCriticalRegion", [apc_disable](vcpu& cpu)
	{
		const auto count = apc_disable(cpu, 1);

		if (count > 0)
			THREAD_LOG_ERR("KeLeaveCriticalRegion: left more regions than were entered (count={})",
				count);
		else
			THREAD_LOG_INFO("KeLeaveCriticalRegion: apc disable count now {}", count);
	});

	// A guarded region holds off special kernel APCs as well, so it drives the
	// other of the thread's two counts -- the one KeAreAllApcsDisabled reads.
	auto special_apc_disable = [](vcpu& cpu, const std::int32_t delta) -> std::int32_t
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t || !t->ethread())
			return 0;

		auto count = t->special_apc_disable();
		const auto updated = static_cast<std::int32_t>(count.read() + delta);

		count.write(static_cast<std::int16_t>(updated));

		return updated;
	};

	state.redirect(mod, "KeEnterGuardedRegion", [special_apc_disable](vcpu& cpu)
	{
		THREAD_LOG_INFO("KeEnterGuardedRegion: special apc disable count now {}",
			special_apc_disable(cpu, -1));
	});

	state.redirect(mod, "KeLeaveGuardedRegion", [special_apc_disable](vcpu& cpu)
	{
		const auto count = special_apc_disable(cpu, 1);

		if (count > 0)
			THREAD_LOG_ERR("KeLeaveGuardedRegion: left more regions than were entered (count={})",
				count);
		else
			THREAD_LOG_INFO("KeLeaveGuardedRegion: special apc disable count now {}", count);
	});

	register_fast_mutexes(state, mod);
}
