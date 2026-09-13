#include "nt_wait_ops.hpp"
#include "../win_kernel.hpp"
#include "../dispatcher.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../thread.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <string_view>
#include <vector>

namespace
{

// WaitType.
constexpr std::uint32_t wait_all = 0;

// How many objects one wait can name, which is what the guest is allowed to
// pass and what bounds the work the scheduler does per look.
constexpr std::size_t maximum_wait_objects = 64;

// A null pointer is a wait with no timeout, a negative value an interval from
// now, and a positive one an absolute guest time. The deadline is worked out
// once, here, because it is relative to when the caller asked.
win_thread::wait_state make_wait(std::vector<addr_t> objects,
	const std::uint32_t wait_type, const emu_object<std::int64_t>& timeout)
{
	win_thread::wait_state w{};
	w.objects = std::move(objects);
	w.all = wait_type == wait_all;

	if (!timeout)
		return w;

	const auto ticks = timeout.read();

	w.timed = true;
	w.deadline = ticks < 0
		? static_cast<std::int64_t>(win_system_time()) - ticks
		: ticks;

	return w;
}

}

// The waits. A thread that cannot proceed is parked on its objects and taken
// off the queue, and whoever signals one of them hands it over -- so a wait
// really does block, and the handlers that signal really do release it.
//
// Deciding a wait means reading the objects, which only works with a thread on
// the cpu. So the signaller does it, and all the scheduler ever looks at is
// whether the wait has been satisfied or has run out of time.
void modules::register_ntoskrnl_wait_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// The wait is set up once. If it can be satisfied straight away the
	// scheduler does that before the thread runs again, so there is no fast
	// path here and no result to write: either way the thread comes back with
	// what the scheduler gave it.
	auto begin_wait = [](vcpu& cpu, std::vector<addr_t> objects, const std::uint32_t wait_type,
		const emu_object<std::int64_t>& timeout, const std::string_view who) -> NTSTATUS
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t)
		{
			THREAD_LOG_ERR("{}: nothing is running, so nothing can wait", who);
			return STATUS_INVALID_PARAMETER;
		}

		auto wait = make_wait(std::move(objects), wait_type, timeout);

		THREAD_LOG_INFO("{}: waiting on {} object(s), {}{}",
			who, wait.objects.size(), wait.all ? "all of them, " : "",
			wait.timed ? "with a timeout" : "with no timeout");

		t->begin_wait(std::move(wait));

		// Asked once here, on the cpu: an object that is already signalled
		// releases the wait without it ever going to sleep, and this is the only
		// place guest memory can be read for it.
		t->try_satisfy(*cpu.curr_addr_space());

		// Off the cpu either way. The scheduler decides when the thread runs
		// again and writes the status over the one returned here.
		thread_scheduler::yield_current(cpu);

		return STATUS_SUCCESS;
	};

	// KeWaitForSingleObject takes the object itself, which is what a driver
	// holds for anything it initialised with Ke*.
	state.redirect(mod, "KeWaitForSingleObject",
		[begin_wait](vcpu& cpu, const addr_t object, const std::uint32_t wait_reason,
			const std::uint8_t wait_mode, const bool alertable,
			emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			if (!object)
				return STATUS_INVALID_PARAMETER;

			if (alertable)
				THREAD_LOG_WARN("KeWaitForSingleObject: nothing delivers an APC, so an alertable "
					"wait runs its course (reason={}, mode={})", wait_reason, wait_mode);

			return begin_wait(cpu, {object}, 1, timeout, "KeWaitForSingleObject");
		});

	state.redirect(mod, "KeWaitForMultipleObjects",
		[begin_wait](vcpu& cpu, const std::uint32_t count, const addr_t object_array,
			const std::uint32_t wait_type, const std::uint32_t wait_reason,
			const std::uint8_t wait_mode, const bool alertable,
			emu_object<std::int64_t> timeout, const addr_t wait_block_array) -> NTSTATUS
		{
			if (!count || count > maximum_wait_objects || !object_array)
				return STATUS_INVALID_PARAMETER;

			auto& space = *cpu.curr_addr_space();

			// An array of pointers to the objects, not the objects themselves.
			std::vector<addr_t> objects(count);

			for (std::uint32_t i = 0; i < count; ++i)
				objects[i] = space.read_mem<addr_t>(object_array + i * sizeof(addr_t));

			if (alertable)
				THREAD_LOG_WARN("KeWaitForMultipleObjects: nothing delivers an APC, so an "
					"alertable wait runs its course (reason={}, mode={}, blocks=0x{:X})",
					wait_reason, wait_mode, wait_block_array);

			return begin_wait(cpu, std::move(objects), wait_type, timeout,
				"KeWaitForMultipleObjects");
		});

	// The Nt forms take handles, and the object behind each is the same one the
	// Ke forms are handed directly.
	auto object_of = [st](const std::uint64_t handle) -> addr_t
	{
		const auto entry = st->sys_proc->handle_table().lookup_handle(handle);

		return entry ? entry->body_addr : 0;
	};

	state.redirect_ntzw(mod, "WaitForSingleObject",
		[begin_wait, object_of](vcpu& cpu, const std::uint64_t handle, const bool alertable,
			emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			const auto object = object_of(handle);

			if (!object)
			{
				THREAD_LOG_WARN("NtWaitForSingleObject: handle 0x{:X} is not open", handle);
				return STATUS_INVALID_HANDLE;
			}

			if (alertable)
				THREAD_LOG_WARN("NtWaitForSingleObject: nothing delivers an APC, so an alertable "
					"wait runs its course");

			return begin_wait(cpu, {object}, 1, timeout, "NtWaitForSingleObject");
		});

	state.redirect_ntzw(mod, "WaitForMultipleObjects",
		[begin_wait, object_of](vcpu& cpu, const std::uint32_t count, const addr_t handle_array,
			const std::uint32_t wait_type, const bool alertable,
			emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			if (!count || count > maximum_wait_objects || !handle_array)
				return STATUS_INVALID_PARAMETER;

			auto& space = *cpu.curr_addr_space();
			std::vector<addr_t> objects(count);

			for (std::uint32_t i = 0; i < count; ++i)
			{
				const auto handle = space.read_mem<std::uint64_t>(
					handle_array + i * sizeof(std::uint64_t));

				objects[i] = object_of(handle);

				if (!objects[i])
				{
					THREAD_LOG_WARN("NtWaitForMultipleObjects: handle 0x{:X} is not open", handle);
					return STATUS_INVALID_HANDLE;
				}
			}

			if (alertable)
				THREAD_LOG_WARN("NtWaitForMultipleObjects: nothing delivers an APC, so an "
					"alertable wait runs its course");

			return begin_wait(cpu, std::move(objects), wait_type, timeout,
				"NtWaitForMultipleObjects");
		});

	// Signalling and waiting as one step, so nothing can take what was signalled
	// and leave the caller waiting for it. The handler runs once, so the signal
	// happens once and the park that follows it cannot be raced.
	state.redirect_ntzw(mod, "SignalAndWaitForSingleObject",
		[st, begin_wait, object_of](vcpu& cpu, const std::uint64_t signal_handle,
			const std::uint64_t wait_handle, const bool alertable,
			emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			const auto signal = object_of(signal_handle);
			const auto object = object_of(wait_handle);

			if (!signal || !object)
				return STATUS_INVALID_HANDLE;

			auto& space = *cpu.curr_addr_space();

			switch (win::type_at(space, signal))
			{
			case win::semaphore_object:
				win::set_state_at(space, signal, win::state_at(space, signal) + 1);
				break;

			case win::mutant_object:
				win::set_state_at(space, signal, win::state_at(space, signal) + 1);
				emu_object<_KMUTANT>(space, signal).field(&_KMUTANT::OwnerThread).write(nullptr);
				break;

			default:
				win::set_state_at(space, signal, 1);
				break;
			}

			THREAD_LOG_INFO("NtSignalAndWaitForSingleObject: signalled 0x{:X}", signal);

			// Before parking, so a thread already waiting on the signalled
			// object gets it rather than losing it to the wait below.
			st->sys_proc->wake_waiters(space, signal);

			if (alertable)
				THREAD_LOG_WARN("NtSignalAndWaitForSingleObject: nothing delivers an APC, so an "
					"alertable wait runs its course");

			return begin_wait(cpu, {object}, 1, timeout, "NtSignalAndWaitForSingleObject");
		});
}
