#include "nt_task_ops.hpp"
#include "../win_kernel.hpp"
#include "../dispatcher.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../thread.hpp"
#include "../types.hpp"
#include "../../../emu/calling_conv.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <chrono>
#include <string_view>
#include <vector>

namespace
{

// THREADINFOCLASS and PROCESSINFOCLASS, the ones answerable from what the
// kernel here actually keeps.
enum thread_information_class : std::uint32_t
{
	thread_basic_information       = 0,
	thread_times                   = 1,
	thread_am_i_last_thread        = 12,
	thread_quantum_reset           = 14,
	thread_hide_from_debugger      = 17,
	thread_is_terminated           = 20,
};

enum process_information_class : std::uint32_t
{
	process_basic_information   = 0,
	process_debug_port          = 7,
	process_wow64_information   = 26,
	process_image_file_name     = 27,
	process_debug_object_handle = 30,
	process_debug_flags         = 31,
	process_cookie              = 36,
	process_tls_information     = 35,
};

// PROCESS_TLS_INFORMATION, followed by one entry per thread, in the order the
// kernel keeps them rather than named by id.
#pragma pack(push, 8)
struct process_tls_information_t
{
	std::uint32_t flags;
	std::uint32_t operation;
	std::uint32_t thread_data_count;
	std::uint32_t tls_index;
	std::uint64_t reserved;
};

struct thread_tls_information_t
{
	std::uint64_t new_tls_data;
	std::uint64_t old_tls_data;
};
#pragma pack(pop)

// PROCESS_TLS_INFORMATION_TYPE.
constexpr std::uint32_t process_tls_replace_index = 0;
constexpr std::uint32_t process_tls_replace_vector = 1;

#pragma pack(push, 8)
struct thread_basic_information_t
{
	NTSTATUS      exit_status;
	std::uint32_t padding;
	addr_t        teb_base_address;
	addr_t        unique_process;
	addr_t        unique_thread;
	std::uint64_t affinity_mask;
	std::int32_t  priority;
	std::int32_t  base_priority;
};

struct process_basic_information_t
{
	NTSTATUS      exit_status;
	std::uint32_t padding;
	addr_t        peb_base_address;
	std::uint64_t affinity_mask;
	std::int32_t  base_priority;
	std::uint32_t padding2;
	addr_t        unique_process_id;
	addr_t        inherited_from_unique_process_id;
};

struct kernel_user_times_t
{
	std::int64_t create_time;
	std::int64_t exit_time;
	std::int64_t kernel_time;
	std::int64_t user_time;
};

struct processor_number_t
{
	std::uint16_t group;
	std::uint8_t  number;
	std::uint8_t  reserved;
};
#pragma pack(pop)

static_assert(sizeof(thread_basic_information_t) == 0x30);
static_assert(sizeof(process_basic_information_t) == 0x30);

// Only the calling thread and the one process are addressable.
constexpr std::uint64_t current_thread_handle = ~std::uint64_t{1};
constexpr std::uint64_t current_process_handle = ~std::uint64_t{0};

std::shared_ptr<win_thread> thread_from_handle(win_kernel_state& state, vcpu& cpu,
	const std::uint64_t handle)
{
	if (handle == current_thread_handle)
		return std::dynamic_pointer_cast<win_thread>(cpu.thread());

	// A thread handle names the ETHREAD, which is a registered object, so the
	// thread it belongs to is found by matching it back.
	const auto entry = state.sys_proc->handle_table().lookup_handle(handle);

	if (!entry)
		return {};

	return state.find_ethread(emu_object<_ETHREAD>(*cpu.curr_addr_space(), entry->body_addr));
}

}

// The thread and process syscalls. Creating, ending and asking about a thread
// all go through the same scheduler and the same ETHREAD the Ps* handlers use,
// so a driver that mixes the two sees one thread rather than two views of one.
void modules::register_ntoskrnl_task_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// The flags a user-mode caller passes are about the process it is creating
	// the thread in, and there is one process here. The attribute list names
	// things -- a client id to fill in, a teb to hand back -- that a kernel
	// caller does not use.
	auto create_thread = [st](vcpu& cpu, emu_object<std::uint64_t> thread_handle,
		const std::uint32_t desired_access,
		[[maybe_unused]] emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const std::uint64_t process_handle, const addr_t start_routine, const addr_t argument,
		const std::uint32_t create_flags, [[maybe_unused]] const std::uint64_t zero_bits,
		[[maybe_unused]] const std::uint64_t stack_size,
		[[maybe_unused]] const std::uint64_t maximum_stack_size,
		const addr_t attribute_list) -> NTSTATUS
	{
		if (!thread_handle || !start_routine)
			return STATUS_INVALID_PARAMETER;

		if (process_handle != 0 && process_handle != current_process_handle)
		{
			THREAD_LOG_WARN("NtCreateThreadEx: process handle 0x{:X} is not this process",
				process_handle);
			return STATUS_INVALID_HANDLE;
		}

		const std::uint64_t args[] = { argument };
		auto t = st->sys_proc->create_thread(cpu, start_routine, args);

		const auto ethread = std::static_pointer_cast<win_thread>(t)->ethread().address();

		if (!ethread)
		{
			THREAD_LOG_ERR("NtCreateThreadEx: tid={} has no ETHREAD", t->id());
			return STATUS_NO_MEMORY;
		}

		const auto handle = st->sys_proc->handle_table().create_handle(ethread, desired_access);
		thread_handle.write(handle);

		THREAD_LOG_INFO("NtCreateThreadEx(start=0x{:X}, argument=0x{:X}, flags=0x{:X}, "
			"attributes=0x{:X}) -> tid={}, handle=0x{:X}",
			start_routine, argument, create_flags, attribute_list, t->id(), handle);

		return STATUS_SUCCESS;
	};

	// A thread is opened by client id, which is the only name one has here.
	auto open_thread = [st](vcpu&, emu_object<std::uint64_t> thread_handle,
		const std::uint32_t desired_access,
		[[maybe_unused]] emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		emu_object<_CLIENT_ID> client_id) -> NTSTATUS
	{
		if (!thread_handle)
			return STATUS_INVALID_PARAMETER;

		thread_handle.write(0);

		if (!client_id)
		{
			THREAD_LOG_WARN("NtOpenThread: nothing here names a thread, so a client id is the "
				"only way to open one");
			return STATUS_INVALID_PARAMETER;
		}

		const auto tid = guest_va(client_id.field(&_CLIENT_ID::UniqueThread).read());
		const auto t = std::dynamic_pointer_cast<win_thread>(
			st->find_thread(static_cast<process::thread_id_type>(tid)));

		const auto ethread = t ? t->ethread().address() : 0;

		if (!ethread)
		{
			THREAD_LOG_WARN("NtOpenThread: no thread {}", tid);
			return STATUS_INVALID_CID;
		}

		st->objs.reference_object(ethread);
		const auto handle = st->sys_proc->handle_table().create_handle(ethread, desired_access);

		thread_handle.write(handle);

		THREAD_LOG_INFO("NtOpenThread(tid={}) -> handle=0x{:X}", tid, handle);

		return STATUS_SUCCESS;
	};

	// Ending the calling thread does not return, which is why the status below
	// is only reached when some other thread is named.
	auto terminate_thread = [st](vcpu& cpu, const std::uint64_t thread_handle,
		const NTSTATUS exit_status) -> NTSTATUS
	{
		const auto t = thread_from_handle(*st, cpu, thread_handle);
		const auto self = cpu.thread();

		if (!t)
		{
			THREAD_LOG_WARN("NtTerminateThread: handle 0x{:X} is not a thread", thread_handle);
			return STATUS_INVALID_HANDLE;
		}

		THREAD_LOG_INFO("NtTerminateThread(tid={}, status=0x{:X})", t->id(), exit_status);

		if (t == self)
		{
			t->finish();
			cpu.stop();
			return STATUS_SUCCESS;
		}

		st->sys_proc->terminate_thread(t->id());

		return STATUS_SUCCESS;
	};

	// The interval is 100ns units, negative for a delay from now. This is
	// KeDelayExecutionThread with the arguments in a different order.
	auto delay_execution = [](vcpu& cpu, const bool alertable,
		emu_object<std::int64_t> delay_interval) -> NTSTATUS
	{
		if (!delay_interval)
			return STATUS_INVALID_PARAMETER;

		const auto ticks = delay_interval.read();
		const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			win_ticks(ticks < 0 ? -ticks : ticks - win_system_time()));

		THREAD_LOG_INFO("NtDelayExecution(alertable={}, interval={}): {}ms",
			alertable, ticks, ms.count());

		if (ms > std::chrono::milliseconds::zero())
			thread_scheduler::sleep_current(cpu, ms);
		else
			thread_scheduler::yield_current(cpu);

		return STATUS_SUCCESS;
	};

	auto query_thread = [st](vcpu& cpu, const std::uint64_t thread_handle,
		const std::uint32_t thread_information_class, const addr_t thread_information,
		const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
	{
		const auto t = thread_from_handle(*st, cpu, thread_handle);

		if (!t)
			return STATUS_INVALID_HANDLE;

		auto& space = *cpu.curr_addr_space();

		switch (thread_information_class)
		{
		case thread_basic_information:
		{
			if (return_length)
				return_length.write(sizeof(thread_basic_information_t));

			if (length < sizeof(thread_basic_information_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			thread_basic_information_t info{};
			info.unique_process = st->sys_proc->id();
			info.unique_thread = t->id();
			info.affinity_mask = 1;

			emu_object<thread_basic_information_t>(space, thread_information).write(info);

			THREAD_LOG_INFO("NtQueryInformationThread(tid={}, ThreadBasicInformation)", t->id());

			return STATUS_SUCCESS;
		}

		case thread_times:
		{
			if (return_length)
				return_length.write(sizeof(kernel_user_times_t));

			if (length < sizeof(kernel_user_times_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			// Nothing accounts cpu time, so the only honest figure is the one
			// that says none has been charged.
			kernel_user_times_t times{};
			times.create_time = static_cast<std::int64_t>(win_system_time());

			emu_object<kernel_user_times_t>(space, thread_information).write(times);

			THREAD_LOG_WARN("NtQueryInformationThread(tid={}, ThreadTimes): no cpu time is "
				"accounted here, so the kernel and user times are zero", t->id());

			return STATUS_SUCCESS;
		}

		case thread_is_terminated:
		{
			if (return_length)
				return_length.write(sizeof(std::uint32_t));

			if (length < sizeof(std::uint32_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			// Reachable only through a handle, and a terminated thread is off
			// the process, so anything answerable here is still running.
			emu_object<std::uint32_t>(space, thread_information).write(0);

			THREAD_LOG_INFO("NtQueryInformationThread(tid={}, ThreadIsTerminated) -> false",
				t->id());

			return STATUS_SUCCESS;
		}

		// A thread returning from its start routine asks this before deciding
		// whether to end the process with itself.
		case thread_am_i_last_thread:
		{
			if (return_length)
				return_length.write(sizeof(std::uint32_t));

			if (length < sizeof(std::uint32_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			std::size_t live = 0;

			if (const auto proc = std::dynamic_pointer_cast<windows_process>(t->proc()))
				proc->for_each_thread([&](win_thread& other)
				{
					if (!other.is_finished())
						++live;
				});

			const std::uint32_t last = live <= 1 ? 1 : 0;
			emu_object<std::uint32_t>(space, thread_information).write(last);

			THREAD_LOG_INFO("NtQueryInformationThread(tid={}, ThreadAmILastThread) -> {} "
				"({} running)", t->id(), last != 0, live);

			return STATUS_SUCCESS;
		}

		default:
			THREAD_LOG_WARN("NtQueryInformationThread: unhandled class {}",
				thread_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}
	};

	auto query_process = [st](vcpu& cpu, const std::uint64_t process_handle,
		const std::uint32_t process_information_class, const addr_t process_information,
		const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
	{
		if (process_handle != 0 && process_handle != current_process_handle)
		{
			const auto entry = st->sys_proc->handle_table().lookup_handle(process_handle);

			if (!entry)
				return STATUS_INVALID_HANDLE;
		}

		auto& space = *cpu.curr_addr_space();

		switch (process_information_class)
		{
		case process_basic_information:
		{
			if (return_length)
				return_length.write(sizeof(process_basic_information_t));

			if (length < sizeof(process_basic_information_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			process_basic_information_t info{};
			info.unique_process_id = st->sys_proc->id();
			info.affinity_mask = 1;
			info.base_priority = 8;

			emu_object<process_basic_information_t>(space, process_information).write(info);

			THREAD_LOG_INFO("NtQueryInformationProcess(ProcessBasicInformation) -> pid={}",
				st->sys_proc->id());

			return STATUS_SUCCESS;
		}

		// Nothing debugs the guest, and a driver checking for a debugger is
		// asking a question with a real answer: there is not one.
		case process_debug_port:
		case process_debug_object_handle:
		{
			if (return_length)
				return_length.write(sizeof(addr_t));

			if (length < sizeof(addr_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			emu_object<addr_t>(space, process_information).write(0);

			THREAD_LOG_INFO("NtQueryInformationProcess(class={}) -> no debugger",
				process_information_class);

			return process_information_class == process_debug_object_handle
				? STATUS_PORT_NOT_SET : STATUS_SUCCESS;
		}

		// Everything here is 64-bit, so nothing is running under wow64.
		case process_wow64_information:
		{
			if (return_length)
				return_length.write(sizeof(addr_t));

			if (length < sizeof(addr_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			emu_object<addr_t>(space, process_information).write(0);

			THREAD_LOG_INFO("NtQueryInformationProcess(ProcessWow64Information) -> not wow64");

			return STATUS_SUCCESS;
		}

		// What RtlEncodePointer xors with. Any value will do, as long as it is
		// the same every time.
		case process_cookie:
		{
			if (return_length)
				return_length.write(sizeof(std::uint32_t));

			if (length < sizeof(std::uint32_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			constexpr std::uint32_t cookie = 0x1EE7C0DE;
			emu_object<std::uint32_t>(space, process_information).write(cookie);

			THREAD_LOG_INFO("NtQueryInformationProcess(ProcessCookie) -> 0x{:X}", cookie);

			return STATUS_SUCCESS;
		}

		default:
			THREAD_LOG_WARN("NtQueryInformationProcess: unhandled class {}",
				process_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}
	};

	// Nothing here acts on any of these -- there is no debugger to hide from
	// and no quantum to reset -- so they are accepted and recorded in the log
	// rather than changing anything.
	auto set_thread = [st](vcpu& cpu, const std::uint64_t thread_handle,
		const std::uint32_t thread_information_class, const addr_t thread_information,
		const std::uint32_t length) -> NTSTATUS
	{
		const auto t = thread_from_handle(*st, cpu, thread_handle);

		if (!t)
			return STATUS_INVALID_HANDLE;

		switch (thread_information_class)
		{
		case thread_hide_from_debugger:
		case thread_quantum_reset:
			THREAD_LOG_INFO("NtSetInformationThread(tid={}, class={}): accepted, and nothing "
				"here acts on it", t->id(), thread_information_class);
			return STATUS_SUCCESS;

		default:
			THREAD_LOG_WARN("NtSetInformationThread(tid={}, class={}, buffer=0x{:X}/{}): "
				"unhandled class", t->id(), thread_information_class, thread_information, length);
			return STATUS_INVALID_INFO_CLASS;
		}
	};

	auto set_process = [](vcpu& cpu, const std::uint64_t process_handle,
		const std::uint32_t process_information_class, const addr_t process_information,
		const std::uint32_t length) -> NTSTATUS
	{
		switch (process_information_class)
		{
		case process_tls_information:
		{
			if (length < sizeof(process_tls_information_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			auto& space = *cpu.curr_addr_space();
			const auto header =
				emu_object<process_tls_information_t>(space, process_information).read();

			if (header.operation != process_tls_replace_vector)
			{
				THREAD_LOG_WARN("NtSetInformationProcess(ProcessTlsInformation): "
					"operation {} is not the vector swap", header.operation);
				return STATUS_INVALID_PARAMETER;
			}

			const auto entries = process_information + sizeof(process_tls_information_t);
			const auto room = (length - sizeof(process_tls_information_t))
				/ sizeof(thread_tls_information_t);

			if (header.thread_data_count > room)
				return STATUS_INFO_LENGTH_MISMATCH;

			const auto t = cpu.thread();
			const auto proc = t ? std::dynamic_pointer_cast<windows_process>(t->proc()) : nullptr;

			if (!proc)
				return STATUS_INVALID_HANDLE;

			// Each entry says what the thread's vector becomes; the value it had
			// goes back in the same entry for the loader to free.
			std::uint32_t index = 0;

			proc->for_each_thread([&](win_thread& other)
			{
				if (index >= header.thread_data_count)
					return;

				const auto& teb = other.teb();

				if (!teb)
					return;

				emu_object<thread_tls_information_t> entry(space,
					entries + index * sizeof(thread_tls_information_t));

				auto data = entry.read();
				auto slot = teb.field(&_TEB64::ThreadLocalStoragePointer);

				data.old_tls_data = slot.read();
				slot.write(data.new_tls_data);

				entry.write(data);
				++index;
			});

			THREAD_LOG_INFO("NtSetInformationProcess(ProcessTlsInformation): swapped the tls "
				"vector of {} of {} thread(s)", index, header.thread_data_count);

			return STATUS_SUCCESS;
		}

		case process_debug_flags:
			THREAD_LOG_INFO("NtSetInformationProcess(class={}): accepted, and nothing here "
				"acts on it", process_information_class);
			return STATUS_SUCCESS;

		default:
			THREAD_LOG_WARN("NtSetInformationProcess(handle=0x{:X}, class={}, buffer=0x{:X}/{}): "
				"unhandled class",
				process_handle, process_information_class, process_information, length);
			return STATUS_INVALID_INFO_CLASS;
		}
	};

	// The scheduler passes over a suspended thread, so suspending the calling
	// one has to give the cpu up on the way out.
	auto suspend_thread = [st](vcpu& cpu, const std::uint64_t thread_handle,
		emu_object<std::uint32_t> previous_count) -> NTSTATUS
	{
		const auto t = thread_from_handle(*st, cpu, thread_handle);

		if (!t)
		{
			THREAD_LOG_WARN("NtSuspendThread: handle 0x{:X} is not a thread", thread_handle);
			return STATUS_INVALID_HANDLE;
		}

		const auto previous = t->suspend();

		if (previous_count)
			previous_count.write(previous);

		THREAD_LOG_INFO("NtSuspendThread(tid={}) -> was suspended {} time(s)",
			t->id(), previous);

		if (t == cpu.thread())
			thread_scheduler::yield_current(cpu);

		return STATUS_SUCCESS;
	};

	auto resume_thread = [st](vcpu& cpu, const std::uint64_t thread_handle,
		emu_object<std::uint32_t> previous_count) -> NTSTATUS
	{
		const auto t = thread_from_handle(*st, cpu, thread_handle);

		if (!t)
		{
			THREAD_LOG_WARN("NtResumeThread: handle 0x{:X} is not a thread", thread_handle);
			return STATUS_INVALID_HANDLE;
		}

		const auto previous = t->resume();

		if (previous_count)
			previous_count.write(previous);

		if (!previous)
			THREAD_LOG_WARN("NtResumeThread: tid={} was not suspended", t->id());
		else
			THREAD_LOG_INFO("NtResumeThread(tid={}) -> was suspended {} time(s)",
				t->id(), previous);

		return STATUS_SUCCESS;
	};

	// The alert is aimed at the thread rather than at the address the waiter
	// passes, so the wait names no object and only an alert or a timeout ends it.
	auto alert_thread = [st](vcpu& cpu, const std::uint64_t thread_id) -> NTSTATUS
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(
			st->find_thread(static_cast<process::thread_id_type>(thread_id)));

		if (!t)
		{
			THREAD_LOG_WARN("NtAlertThreadByThreadId: no thread {}", thread_id);
			return STATUS_INVALID_CID;
		}

		t->alert();

		THREAD_LOG_INFO("NtAlertThreadByThreadId(tid={})", t->id());

		return STATUS_SUCCESS;
	};

	auto wait_for_alert = [](vcpu& cpu, const addr_t address,
		emu_object<std::int64_t> timeout) -> NTSTATUS
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		if (!t)
			return STATUS_INVALID_PARAMETER;

		if (t->take_alert())
		{
			THREAD_LOG_INFO("NtWaitForAlertByThreadId(0x{:X}): an alert was already in hand",
				address);
			return STATUS_SUCCESS;
		}

		const auto when = win::read_timeout(timeout);

		win_thread::wait_state wait{};
		wait.deadline = when.deadline;
		wait.timed = when.timed;

		THREAD_LOG_INFO("NtWaitForAlertByThreadId(0x{:X}): parked {}",
			address, wait.timed ? "with a timeout" : "with no timeout");

		t->begin_wait(std::move(wait));
		thread_scheduler::yield_current(cpu);

		return STATUS_SUCCESS;
	};

	// The status a thread that has not impersonated anyone gets on real Windows.
	auto open_thread_token = [](vcpu&, const std::uint64_t thread_handle,
		const std::uint32_t desired_access, const bool open_as_self,
		emu_object<std::uint64_t> token_handle) -> NTSTATUS
	{
		if (token_handle)
			token_handle.write(0);

		THREAD_LOG_WARN("NtOpenThreadToken(handle=0x{:X}, access=0x{:X}, as_self={}): nothing "
			"here carries a token", thread_handle, desired_access, open_as_self);

		return STATUS_NO_TOKEN;
	};

	auto open_thread_token_ex = [open_thread_token](vcpu& cpu, const std::uint64_t thread_handle,
		const std::uint32_t desired_access, const bool open_as_self,
		[[maybe_unused]] const std::uint32_t handle_attributes,
		emu_object<std::uint64_t> token_handle) -> NTSTATUS
	{
		return open_thread_token(cpu, thread_handle, desired_access, open_as_self,
			std::move(token_handle));
	};

	// Ends the thread asking too, so it does not return.
	auto terminate_process = [st](vcpu& cpu, const std::uint64_t process_handle,
		const NTSTATUS exit_status) -> NTSTATUS
	{
		if (process_handle != 0 && process_handle != current_process_handle)
		{
			THREAD_LOG_WARN("NtTerminateProcess: handle 0x{:X} is not this process",
				process_handle);
			return STATUS_INVALID_HANDLE;
		}

		const auto self = cpu.thread();

		// Collected first: terminate_thread takes the lock for_each_thread holds.
		std::vector<process::thread_id_type> ids;

		st->sys_proc->for_each_thread([&](win_thread& t)
		{
			if (!self || t.id() != self->id())
				ids.push_back(t.id());
		});

		THREAD_LOG_INFO("NtTerminateProcess(status=0x{:X}): ending {} other thread(s)",
			exit_status, ids.size());

		for (const auto id : ids)
			st->sys_proc->terminate_thread(id);

		if (self)
			self->finish();

		cpu.stop();

		return STATUS_SUCCESS;
	};

	// One group, and the cpu the caller is on is the one it is asking about.
	state.redirect_ntzw(mod, "GetCurrentProcessorNumber", [](vcpu& cpu) -> std::uint32_t
	{
		const auto id = static_cast<std::uint32_t>(cpu.id());
		THREAD_LOG_INFO("NtGetCurrentProcessorNumber() -> {}", id);
		return id;
	});

	auto current_processor_ex = [](vcpu& cpu,
		emu_object<processor_number_t> processor_number) -> std::uint32_t
	{
		const auto id = static_cast<std::uint32_t>(cpu.id());

		if (processor_number)
		{
			processor_number_t number{};
			number.number = static_cast<std::uint8_t>(id);
			processor_number.write(number);
		}

		THREAD_LOG_INFO("NtGetCurrentProcessorNumberEx() -> group 0, {}", id);

		return id;
	};

	state.redirect_ntzw(mod, "GetCurrentProcessorNumberEx", current_processor_ex);

	state.redirect_ntzw(mod, "YieldExecution", [](vcpu& cpu) -> NTSTATUS
	{
		THREAD_LOG_INFO("NtYieldExecution()");
		thread_scheduler::yield_current(cpu);
		return STATUS_SUCCESS;
	});

	state.redirect_ntzw(mod, "CreateThreadEx", create_thread);
	state.redirect_ntzw(mod, "OpenThread", open_thread);
	state.redirect_ntzw(mod, "TerminateThread", terminate_thread);
	state.redirect_ntzw(mod, "DelayExecution", delay_execution);
	state.redirect_ntzw(mod, "QueryInformationThread", query_thread);
	state.redirect_ntzw(mod, "QueryInformationProcess", query_process);
	state.redirect_ntzw(mod, "SetInformationThread", set_thread);
	state.redirect_ntzw(mod, "SetInformationProcess", set_process);
	state.redirect_ntzw(mod, "SuspendThread", suspend_thread);
	state.redirect_ntzw(mod, "ResumeThread", resume_thread);
	// Nothing queues a user APC, so there is never anything pending.
	state.redirect_ntzw(mod, "TestAlert", [](vcpu&) -> NTSTATUS
	{
		THREAD_LOG_INFO("NtTestAlert(): nothing queues an alert here");
		return STATUS_SUCCESS;
	});

	state.redirect_ntzw(mod, "AlertThreadByThreadId", alert_thread);
	state.redirect_ntzw(mod, "WaitForAlertByThreadId", wait_for_alert);
	state.redirect_ntzw(mod, "OpenThreadToken", open_thread_token);
	state.redirect_ntzw(mod, "OpenThreadTokenEx", open_thread_token_ex);
	state.redirect_ntzw(mod, "TerminateProcess", terminate_process);
}
