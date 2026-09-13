#include "nt_wait_ops.hpp"
#include "../win_kernel.hpp"
#include "../dispatcher.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../thread.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <chrono>
#include <string_view>
#include <vector>

namespace
{

// WaitType.
constexpr std::uint32_t wait_all = 0;
constexpr std::uint32_t wait_any = 1;

// How many objects one wait can name, which is what the guest is allowed to
// pass and what bounds the work done per re-entry.
constexpr std::size_t maximum_wait_objects = 64;

// The deadline the wait runs against, worked out once and remembered: the
// caller's timeout is relative to when it asked, not to each re-check.
//
// A null pointer is a wait with no timeout; a negative value is an interval
// from now; a positive one is an absolute guest time.
win_kernel_state::thread_wait begin_wait(const addr_t call,
	const emu_object<std::int64_t>& timeout)
{
	win_kernel_state::thread_wait w{};
	w.call = call;

	if (!timeout)
		return w;

	const auto ticks = timeout.read();

	w.timed = true;
	w.deadline = ticks < 0
		? static_cast<std::int64_t>(win_system_time()) - ticks
		: ticks;

	return w;
}

[[nodiscard]] bool expired(const win_kernel_state::thread_wait& w)
{
	return w.timed && static_cast<std::int64_t>(win_system_time()) >= w.deadline;
}

// A wait that is not satisfied yet: the thread gives up its cpu and comes back
// to the same call, so nothing else is blocked while it waits.
void wait_again(vcpu& cpu)
{
	thread_scheduler::sleep_current(cpu, win::wait_poll_interval);
	cpu.repeat();
}

// The ETHREAD of whoever is waiting, which is what a mutant records as its
// owner and what makes a recursive acquire recursive.
addr_t waiter(vcpu& cpu)
{
	const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());
	return t ? t->ethread().address() : 0;
}

}

// The waits. A thread that cannot proceed leaves its cpu and is entered again
// at the same call until its objects are signalled or its timeout runs out --
// so a wait really does block, and the handlers that signal really do release
// it. What is missing is the wait list: nothing is woken by the signal itself,
// so a release is noticed on the next re-check rather than immediately.
void modules::register_ntoskrnl_wait_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// One wait per thread, remembered across the re-entries it takes. A thread
	// that reaches a different call has left the first wait behind, so the
	// entry is replaced rather than kept.
	auto wait_for = [st](vcpu& cpu, const addr_t call,
		const std::vector<addr_t>& objects, const std::uint32_t wait_type,
		const emu_object<std::int64_t>& timeout, const std::string_view who) -> NTSTATUS
	{
		auto& space = *cpu.curr_addr_space();
		const auto t = cpu.thread();
		const auto id = t ? t->id() : 0;
		const auto self = waiter(cpu);

		auto& waits = st->waits;
		auto it = waits.find(id);

		if (it == waits.end() || it->second.call != call)
		{
			it = waits.insert_or_assign(id, begin_wait(call, timeout)).first;

			THREAD_LOG_INFO("{}: waiting on {} object(s), {}",
				who, objects.size(),
				it->second.timed ? "with a timeout" : "with no timeout");
		}

		// WaitAny is satisfied by the first signalled object; WaitAll needs
		// every one of them, and takes none until all are available -- which is
		// what keeps two threads from each taking half of what they need.
		std::size_t satisfied = objects.size();

		if (wait_type == wait_any)
		{
			satisfied = objects.size();

			for (std::size_t i = 0; i < objects.size(); ++i)
			{
				if (win::is_signalled(space, objects[i], self))
				{
					satisfied = i;
					break;
				}
			}

			if (satisfied < objects.size())
			{
				win::take(space, objects[satisfied], self);
				waits.erase(id);

				THREAD_LOG_INFO("{}: object {} at 0x{:X} released the wait",
					who, satisfied, objects[satisfied]);

				return static_cast<NTSTATUS>(satisfied);
			}
		}
		else
		{
			for (const auto object : objects)
			{
				if (!win::is_signalled(space, object, self))
				{
					satisfied = objects.size() + 1;
					break;
				}
			}

			if (satisfied == objects.size())
			{
				for (const auto object : objects)
					win::take(space, object, self);

				waits.erase(id);

				THREAD_LOG_INFO("{}: every object is signalled, so the wait is over", who);

				return STATUS_SUCCESS;
			}
		}

		if (expired(it->second))
		{
			waits.erase(id);

			THREAD_LOG_INFO("{}: the timeout ran out", who);

			return STATUS_TIMEOUT;
		}

		wait_again(cpu);

		// Nothing is written: the handler is entered again and the result is
		// decided then.
		return STATUS_SUCCESS;
	};

	// KeWaitForSingleObject takes the object itself, which is what a driver
	// holds for anything it initialised with Ke*.
	state.redirect(mod, "KeWaitForSingleObject",
		[wait_for](vcpu& cpu, const addr_t object, const std::uint32_t wait_reason,
			const std::uint8_t wait_mode, const bool alertable,
			emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			if (!object)
				return STATUS_INVALID_PARAMETER;

			if (alertable)
				THREAD_LOG_WARN("KeWaitForSingleObject: nothing delivers an APC, so an alertable "
					"wait runs its course (reason={}, mode={})", wait_reason, wait_mode);

			return wait_for(cpu, cpu.pc(), {object}, wait_any, timeout,
				"KeWaitForSingleObject");
		});

	state.redirect(mod, "KeWaitForMultipleObjects",
		[wait_for](vcpu& cpu, const std::uint32_t count, const addr_t object_array,
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

			return wait_for(cpu, cpu.pc(), objects, wait_type, timeout,
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
		[wait_for, object_of](vcpu& cpu, const std::uint64_t handle, const bool alertable,
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

			return wait_for(cpu, cpu.pc(), {object}, wait_any, timeout,
				"NtWaitForSingleObject");
		});

	state.redirect_ntzw(mod, "WaitForMultipleObjects",
		[wait_for, object_of](vcpu& cpu, const std::uint32_t count, const addr_t handle_array,
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

			return wait_for(cpu, cpu.pc(), objects, wait_type, timeout,
				"NtWaitForMultipleObjects");
		});

	// Signalling and waiting as one step, so nothing can take what was signalled
	// and leave the caller waiting for it. The signal happens once -- on the
	// first entry -- and the wait then behaves like any other.
	state.redirect_ntzw(mod, "SignalAndWaitForSingleObject",
		[st, wait_for, object_of](vcpu& cpu, const std::uint64_t signal_handle,
			const std::uint64_t wait_handle, const bool alertable,
			emu_object<std::int64_t> timeout) -> NTSTATUS
		{
			const auto signal = object_of(signal_handle);
			const auto object = object_of(wait_handle);

			if (!signal || !object)
				return STATUS_INVALID_HANDLE;

			auto& space = *cpu.curr_addr_space();
			const auto call = cpu.pc();

			// Only the first time through: a re-entry is the same wait carrying
			// on, and signalling again would release a second waiter.
			const auto t = cpu.thread();
			const auto id = t ? t->id() : 0;
			const auto it = st->waits.find(id);

			if (it == st->waits.end() || it->second.call != call)
			{
				const auto type = win::type_at(space, signal);

				switch (type)
				{
				case win::semaphore_object:
					win::set_state_at(space, signal, win::state_at(space, signal) + 1);
					break;

				case win::mutant_object:
					win::set_state_at(space, signal, win::state_at(space, signal) + 1);
					emu_object<_KMUTANT>(space, signal).field(&_KMUTANT::OwnerThread)
						.write(nullptr);
					break;

				default:
					win::set_state_at(space, signal, 1);
					break;
				}

				THREAD_LOG_INFO("NtSignalAndWaitForSingleObject: signalled 0x{:X}", signal);
			}

			if (alertable)
				THREAD_LOG_WARN("NtSignalAndWaitForSingleObject: nothing delivers an APC, so an "
					"alertable wait runs its course");

			return wait_for(cpu, call, {object}, wait_any, timeout,
				"NtSignalAndWaitForSingleObject");
		});
}
