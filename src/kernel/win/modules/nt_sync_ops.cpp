#include "nt_sync_ops.hpp"
#include "../win_kernel.hpp"
#include "../dispatcher.hpp"
#include "../thread.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"

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
}
