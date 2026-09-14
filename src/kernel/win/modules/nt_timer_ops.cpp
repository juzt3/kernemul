#include "nt_timer_ops.hpp"
#include "../win_kernel.hpp"
#include "../defs.hpp"
#include "../dispatcher.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <chrono>

namespace
{

// KDPC::Type.
constexpr std::uint8_t dpc_object_type = 19;

// KDPC::Importance.
constexpr std::uint8_t medium_importance = 1;

}

// Deferred procedure calls and the timers that queue them. A DPC runs: it is
// started on a thread of its own, which is the closest thing here to the
// dispatch level the real one runs at. A timer does not -- nothing walks a
// timer list -- so a timer records what it was told and says so.
void modules::register_ntoskrnl_timer_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "KeInitializeDpc",
		[](vcpu&, emu_object<_KDPC> dpc, const addr_t deferred_routine,
			const addr_t deferred_context)
		{
			if (!dpc)
				return;

			_KDPC out{};
			out.Type = dpc_object_type;
			out.Importance = medium_importance;
			out.DeferredRoutine = guest_ptr<void>(deferred_routine);
			out.DeferredContext = guest_ptr<void>(deferred_context);

			dpc.write(out);

			THREAD_LOG_INFO("KeInitializeDpc(0x{:X}, routine=0x{:X}, context=0x{:X})",
				dpc.address(), deferred_routine, deferred_context);
		});

	// The real one queues the DPC and runs it when the processor next drops to
	// dispatch level. It runs on a thread of its own here instead, so it runs
	// alongside the caller rather than after it -- a driver relying on the
	// serialisation a real DPC queue gives would notice.
	state.redirect(mod, "KeInsertQueueDpc",
		[st](vcpu& cpu, emu_object<_KDPC> dpc, const addr_t system_argument1,
			const addr_t system_argument2) -> bool
		{
			if (!dpc)
				return false;

			auto entry = dpc.read();
			const auto routine = guest_va(entry.DeferredRoutine);

			if (!routine)
			{
				THREAD_LOG_WARN("KeInsertQueueDpc: 0x{:X} has no deferred routine",
					dpc.address());
				return false;
			}

			// DpcData is what the real one tests to find out whether the object
			// is already on a queue, and what it clears when the DPC runs.
			if (guest_va(entry.DpcData))
			{
				THREAD_LOG_INFO("KeInsertQueueDpc(0x{:X}): already queued", dpc.address());
				return false;
			}

			entry.SystemArgument1 = guest_ptr<void>(system_argument1);
			entry.SystemArgument2 = guest_ptr<void>(system_argument2);
			entry.DpcData = guest_ptr<void>(dpc.address());
			dpc.write(entry);

			// A deferred routine is called with the DPC itself, the context it
			// was initialised with and the two arguments it was queued with.
			const std::uint64_t args[] = {
				dpc.address(),
				guest_va(entry.DeferredContext),
				system_argument1,
				system_argument2,
			};

			auto t = st->sys_proc->create_thread(cpu, routine, args);

			THREAD_LOG_INFO("KeInsertQueueDpc(0x{:X}, 0x{:X}, 0x{:X}): routine 0x{:X} runs as tid={}",
				dpc.address(), system_argument1, system_argument2, routine, t->id());

			return true;
		});

	// Nothing sits on a queue waiting to be drained -- an inserted DPC is
	// already running on its own thread -- so there is nothing to wait for.
	state.redirect(mod, "KeFlushQueuedDpcs", [](vcpu&)
	{
		THREAD_LOG_INFO("KeFlushQueuedDpcs(): a DPC runs when it is inserted, so none are queued");
	});

	// A notification timer stays signalled once it fires and a synchronization
	// timer is taken by one waiter; nothing fires either, but the type is what a
	// driver reads back out of the header.
	state.redirect(mod, "KeInitializeTimer", [](vcpu&, emu_object<_KTIMER> timer)
	{
		if (!timer)
			return;

		win::init_dispatcher(timer, win::timer_notification_object, 0);

		timer.field(&_KTIMER::DueTime).field(&_ULARGE_INTEGER::QuadPart).write(0);
		timer.field(&_KTIMER::Dpc).write(nullptr);
		timer.field(&_KTIMER::Period).write(0);

		THREAD_LOG_INFO("KeInitializeTimer(0x{:X})", timer.address());
	});

	// The due time is negative for an interval and positive for an absolute
	// time, which is the one thing worth reporting about a timer that will not
	// go off.
	state.redirect(mod, "KeSetTimer",
		[](vcpu&, emu_object<_KTIMER> timer, const std::int64_t due_time,
			emu_object<_KDPC> dpc) -> bool
		{
			if (!timer)
				return false;

			auto entry = timer.read();
			const bool was_set = entry.DueTime.QuadPart != 0;

			// A negative due time is an interval from now; the timer list holds
			// absolute times, so that is what DueTime ends up holding.
			const auto absolute = due_time < 0
				? win_system_time() + static_cast<std::uint64_t>(-due_time)
				: static_cast<std::uint64_t>(due_time);

			entry.DueTime.QuadPart = absolute;
			entry.Dpc = guest_ptr<_KDPC>(dpc.address());
			entry.Header.SignalState = 0;
			entry.Period = 0;

			timer.write(entry);

			const auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(
				win_ticks(due_time < 0 ? -due_time : due_time));

			THREAD_LOG_WARN("KeSetTimer(0x{:X}, due={} ({} {} ms) -> absolute 0x{:X}, dpc=0x{:X}): "
				"nothing here walks a timer list, so it will not go off",
				timer.address(), due_time, due_time < 0 ? "in" : "at", interval.count(),
				absolute, dpc.address());

			return was_set;
		});

	state.redirect(mod, "KeCancelTimer", [](vcpu&, emu_object<_KTIMER> timer) -> bool
	{
		if (!timer)
			return false;

		auto entry = timer.read();
		const bool was_set = entry.DueTime.QuadPart != 0;

		entry.DueTime.QuadPart = 0;
		entry.Dpc = nullptr;
		timer.write(entry);

		THREAD_LOG_INFO("KeCancelTimer(0x{:X}) -> {}", timer.address(), was_set);

		return was_set;
	});

	// Never signalled, because nothing fires a timer. A driver polling this
	// instead of waiting sees the same answer the wait would have given it.
	state.redirect(mod, "KeReadStateTimer", [](vcpu&, emu_object<_KTIMER> timer) -> bool
	{
		if (!timer)
			return false;

		const auto signalled = timer.field(&_KTIMER::Header)
			.field(&_DISPATCHER_HEADER::SignalState).read() != 0;

		THREAD_LOG_INFO("KeReadStateTimer(0x{:X}) -> {}", timer.address(), signalled);

		return signalled;
	});

	// The body is a real KTIMER, so a wait on the handle reads the same state a
	// wait on the object would -- which, as above, nothing ever moves.
	state.redirect_ntzw(mod, "CreateTimer2",
		[st](vcpu& cpu, emu_object<std::uint64_t> timer_handle,
			[[maybe_unused]] const addr_t reserved1, [[maybe_unused]] const addr_t reserved2,
			const std::uint32_t attributes, const std::uint32_t desired_access) -> NTSTATUS
		{
			if (!timer_handle)
				return STATUS_INVALID_PARAMETER;

			const _KTIMER zeroed{};
			const auto addr = st->objs.create_object(0, &zeroed, sizeof(zeroed),
				{}, prot_rw | prot_supervisor);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			const emu_object<_KTIMER> timer(*cpu.curr_addr_space(), addr);

			// TIMER_TYPE is the low bit of the attributes.
			win::init_dispatcher(timer, (attributes & 1)
				? win::timer_synchronization_object : win::timer_notification_object, 0);

			const auto handle = st->sys_proc->handle_table().create_handle(addr, desired_access);
			timer_handle.write(handle);

			THREAD_LOG_INFO("NtCreateTimer2(attributes=0x{:X}) -> handle=0x{:X}",
				attributes, handle);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "SetTimer2",
		[st](vcpu& cpu, const std::uint64_t timer_handle, emu_object<std::int64_t> due_time,
			emu_object<std::int64_t> period, const addr_t parameters) -> NTSTATUS
		{
			const auto entry = st->sys_proc->handle_table().lookup_handle(timer_handle);

			if (!entry)
			{
				THREAD_LOG_WARN("NtSetTimer2: handle 0x{:X} is not open", timer_handle);
				return STATUS_INVALID_HANDLE;
			}

			if (!due_time)
				return STATUS_INVALID_PARAMETER;

			const auto when = win::read_timeout(due_time);
			const auto interval = period ? period.read() : 0;

			const emu_object<_KTIMER> timer(*cpu.curr_addr_space(), entry->body_addr);

			timer.field(&_KTIMER::DueTime).field(&_ULARGE_INTEGER::QuadPart)
				.write(static_cast<std::uint64_t>(when.deadline));
			timer.field(&_KTIMER::Period).write(static_cast<std::uint32_t>(
				interval / 10000));

			THREAD_LOG_WARN("NtSetTimer2(0x{:X}, due={}, period={}, parameters=0x{:X}): nothing "
				"here walks a timer list, so it will not go off",
				timer_handle, due_time.read(), interval, parameters);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "CancelTimer2",
		[st](vcpu& cpu, const std::uint64_t timer_handle, const addr_t parameters) -> NTSTATUS
		{
			const auto entry = st->sys_proc->handle_table().lookup_handle(timer_handle);

			if (!entry)
			{
				THREAD_LOG_WARN("NtCancelTimer2: handle 0x{:X} is not open", timer_handle);
				return STATUS_INVALID_HANDLE;
			}

			const emu_object<_KTIMER> timer(*cpu.curr_addr_space(), entry->body_addr);
			const auto due = timer.field(&_KTIMER::DueTime)
				.field(&_ULARGE_INTEGER::QuadPart).read();

			timer.field(&_KTIMER::DueTime).field(&_ULARGE_INTEGER::QuadPart).write(0);
			timer.field(&_KTIMER::Period).write(0);

			THREAD_LOG_INFO("NtCancelTimer2(0x{:X}, parameters=0x{:X}) -> was {}",
				timer_handle, parameters, due ? "set" : "not set");

			return STATUS_SUCCESS;
		});
}
