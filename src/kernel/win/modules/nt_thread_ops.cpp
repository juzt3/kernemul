#include "nt_thread_ops.hpp"
#include "../thread.hpp"
#include "../win_kernel.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <chrono>

void modules::register_ntoskrnl_thread_ops(win_kernel_state& state, proc_module& mod)
{
	auto* sys_proc = state.sys_proc.get();

	// A system thread starts inside this stub in real Windows: it calls the
	// start routine and ends the thread when it returns. Nothing of it is
	// executed here -- threads are given it as their return address, so landing
	// on it means the start routine returned.
	state.redirect(mod, kernel_thread_startup, [](vcpu& cpu)
	{
		if (const auto t = cpu.thread())
			t->finish();

		cpu.stop();
	});

	state.redirect(mod, "PsCreateSystemThread",
		[sys_proc](vcpu& cpu, emu_object<std::uint64_t> thread_handle_out,
			[[maybe_unused]] std::uint32_t desired_access,
			[[maybe_unused]] emu_object<void> object_attributes, [[maybe_unused]] std::uint64_t process_handle,
			emu_object<CLIENT_ID> client_id_out, addr_t start_routine, addr_t start_context) -> NTSTATUS
		{
			THREAD_LOG_INFO("PsCreateSystemThread(handle_out=0x{:X}, start=0x{:X}, ctx=0x{:X})",
				thread_handle_out.address(), start_routine, start_context);

			auto t = sys_proc->create_thread(cpu, start_routine);
			cpu.emu()->call_conv()->set_arg(cpu, *t, 0, start_context);

			// The thread's ETHREAD is already a registered object, so the
			// handle names it directly and the guest can read what it gets.
			const auto ethread = std::static_pointer_cast<win_thread>(t)->ethread().address();

			if (!ethread)
			{
				THREAD_LOG_ERR("PsCreateSystemThread: tid={} has no ETHREAD", t->id());
				return STATUS_NO_MEMORY;
			}

			const auto handle = sys_proc->handle_table().create_handle(ethread, THREAD_ALL_ACCESS);

			if (thread_handle_out)
				thread_handle_out.write(handle);

			if (client_id_out)
			{
				CLIENT_ID cid{};
				cid.UniqueProcess = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(sys_proc->id()));
				cid.UniqueThread = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(t->id()));
				client_id_out.write(cid);
			}

			THREAD_LOG_INFO("PsCreateSystemThread: created tid={}, handle=0x{:X}", t->id(), handle);
			return STATUS_SUCCESS;
		});

	// The interval is in 100ns units: negative is a delay from now, positive an
	// absolute guest time to wait until. Nothing here queues APCs, so an
	// alertable wait has nothing to be interrupted by and always runs its
	// course -- which is why the result is only ever success.
	state.redirect(mod, "KeDelayExecutionThread",
		[](vcpu& cpu, const std::uint8_t wait_mode, const std::uint8_t alertable,
			emu_object<std::int64_t> interval) -> NTSTATUS
		{
			if (!interval)
			{
				THREAD_LOG_ERR("KeDelayExecutionThread: null interval");
				return STATUS_INVALID_PARAMETER;
			}

			const auto ticks = interval.read();
			const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
				win_ticks(ticks < 0 ? -ticks : ticks - win_system_time()));

			THREAD_LOG_INFO("KeDelayExecutionThread(wait_mode={}, alertable={}, interval={}): {}ms",
				wait_mode, alertable, ticks, ms.count());

			// An absolute time already past, or a delay too short to name in
			// milliseconds, is a request to give up the rest of the quantum
			// rather than to wait: the thread is runnable the moment it is off
			// the cpu, so it goes back on the queue awake.
			if (ms > std::chrono::milliseconds::zero())
				thread_scheduler::sleep_current(cpu, ms);
			else
				thread_scheduler::yield_current(cpu);

			return STATUS_SUCCESS;
		});

	// The increment is relative to the owning process's base priority, and what
	// comes back is the increment the thread had before. Nothing here schedules
	// by priority, so moving it changes only what the guest reads back -- which
	// it does, to restore the level it found.
	state.redirect(mod, "KeSetBasePriorityThread",
		[](vcpu& cpu, emu_object<_KTHREAD> thread, const std::int32_t increment) -> std::int32_t
		{
			if (!thread)
				return 0;

			const auto process = guest_va(thread.field(&_KTHREAD::Process).read());

			const auto process_base = process
				? emu_object<_KPROCESS>(*cpu.curr_addr_space(), process)
					.field(&_KPROCESS::BasePriority).read()
				: 0;

			const auto previous = thread.field(&_KTHREAD::BasePriority).read() - process_base;
			const auto updated = static_cast<char>(process_base + increment);

			thread.field(&_KTHREAD::BasePriority).write(updated);
			thread.field(&_KTHREAD::Priority).write(updated);

			THREAD_LOG_INFO("KeSetBasePriorityThread(thread=0x{:X}, increment={}) -> {}",
				thread.address(), increment, previous);

			return previous;
		});

	// The irp a filesystem filter is re-entered under, which is per thread and
	// lives in the ETHREAD rather than anywhere the io manager keeps. Nothing
	// here builds an irp, so what the guest reads back is only ever what the
	// guest itself put there -- which is exactly what a filter checks it for.
	state.redirect(mod, "IoGetTopLevelIrp", [](vcpu& cpu) -> addr_t
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t || !t->ethread())
		{
			THREAD_LOG_WARN("IoGetTopLevelIrp: no current thread");
			return 0;
		}

		const auto irp = t->ethread().field(&_ETHREAD::TopLevelIrp).read();

		THREAD_LOG_INFO("IoGetTopLevelIrp() -> 0x{:X}", irp);

		return irp;
	});

	state.redirect(mod, "IoSetTopLevelIrp", [](vcpu& cpu, const addr_t irp)
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t || !t->ethread())
		{
			THREAD_LOG_ERR("IoSetTopLevelIrp: no current thread to set 0x{:X} on", irp);
			return;
		}

		t->ethread().field(&_ETHREAD::TopLevelIrp).write(irp);

		THREAD_LOG_INFO("IoSetTopLevelIrp(0x{:X})", irp);
	});
}
