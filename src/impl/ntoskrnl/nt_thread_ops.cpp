#include "nt_thread_ops.hpp"
#include "../../kernel/thread.hpp"
#include "../../user/user.hpp"
#include "../../user/user_memory.hpp"
#include "../../user/user_defs.hpp"

constexpr std::uint32_t status_success = 0x00000000;
constexpr std::uint32_t status_timeout = 0x00000102;
constexpr std::uint32_t status_invalid_handle = 0xC0000008;
constexpr std::uint32_t status_invalid_parameter = 0xC000000D;
constexpr std::uint32_t status_no_token = 0xC000007C;
constexpr std::uint32_t status_not_implemented = 0xC0000002;

// NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
static void handle_delay_execution(const std::shared_ptr<emulator_t>& emulator,
	std::uint32_t alertable, emulator_t::address_type delay_interval_ptr)
{
	std::int64_t delay_interval = 0;

	if (delay_interval_ptr)
	{
		emulator_err_t error = emulator->read_virtual_memory(delay_interval_ptr, &delay_interval, sizeof(delay_interval));
		error.throw_if("NtDelayExecution: read delay interval");
	}

	THREAD_LOG("NtDelayExecution called (alertable={}, interval={})", alertable, delay_interval);

	if (delay_interval < 0)
	{
		// relative time in 100ns units
		const auto ms = static_cast<std::uint64_t>(-delay_interval) / 10000;
		if (kernel::current_thread && ms > 0)
		{
			kernel::current_thread->sleep_for(std::chrono::milliseconds(ms > 5000 ? 5000 : ms));
		}
	}
	else if (delay_interval == 0)
	{
		// yield
	}

	write_nt_success(emulator);
}

static void handle_terminate_thread(bool& skip_return, const std::shared_ptr<emulator_t>& emulator,
	kernel::handle_t thread_handle, std::uint32_t exit_status)
{
	THREAD_LOG("NtTerminateThread called (handle=0x{:X}, exit_status=0x{:X})",
		thread_handle, exit_status);

	if (thread_handle == 0 || thread_handle == static_cast<kernel::handle_t>(-1) ||
		thread_handle == static_cast<kernel::handle_t>(-2))
	{
		THREAD_LOG("NtTerminateThread: terminating current thread");

		constexpr emulator_t::address_type sentinel = 0xFFFFFFFFFFFFFFFF;
		emulator->write_register<x86::reg::rip>(sentinel);
		write_nt_success(emulator);
		skip_return = true;
		return;
	}

	const auto thread_obj = kernel::active_handle_table().get_object_from_handle<thread_object_t>(thread_handle);
	if (!thread_obj)
	{
		THREAD_WARN_LOG("NtTerminateThread: invalid handle 0x{:X}", thread_handle);
		write_nt_status(emulator, status_invalid_handle);
		return;
	}

	THREAD_LOG("NtTerminateThread: terminating thread {} (stub - marked done)",
		thread_obj->thread->id());
	write_nt_success(emulator);
}

// NtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
static void handle_open_thread(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes, emulator_t::address_type client_id_ptr)
{
	std::uint64_t target_thread_id = 0;

	if (client_id_ptr)
	{
		// CLIENT_ID: { UniqueProcess, UniqueThread }
		emulator_err_t error = emulator->read_virtual_memory(client_id_ptr + 8, &target_thread_id, sizeof(target_thread_id));
		error.throw_if("NtOpenThread: read client id");
	}

	THREAD_LOG("NtOpenThread called (handle_out=0x{:X}, access=0x{:X}, tid={})",
		handle_out, desired_access, target_thread_id);

	// only current thread is directly accessible
	if (kernel::current_thread &&
		(target_thread_id == 0 || kernel::current_thread->id() == target_thread_id))
	{
		auto thread_obj = std::make_shared<thread_object_t>(kernel::current_thread);

		_ETHREAD body = {};
		const auto body_address = kernel::object_manager->create_object(0, &body, sizeof(body), thread_obj);
		const auto handle = kernel::active_handle_table().create_handle(body_address, desired_access);

		if (handle_out)
		{
			emulator_err_t error = emulator->write_virtual_memory(handle_out, &handle, sizeof(handle));
			error.throw_if("NtOpenThread: write handle");
		}

		THREAD_LOG("NtOpenThread: opened handle 0x{:X} for tid {}", handle, target_thread_id);
		write_nt_success(emulator);
		return;
	}

	THREAD_WARN_LOG("NtOpenThread: thread {} not found", target_thread_id);
	write_nt_status(emulator, status_invalid_parameter);
}

// NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
static void handle_suspend_thread(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type thread_handle, emulator_t::address_type previous_count_ptr)
{
	THREAD_LOG("NtSuspendThread called (handle=0x{:X}, previous=0x{:X}) - stub",
		thread_handle, previous_count_ptr);

	if (previous_count_ptr)
	{
		const std::uint32_t previous = 0;
		emulator_err_t error = emulator->write_virtual_memory(previous_count_ptr, &previous, sizeof(previous));
		error.throw_if("NtSuspendThread: write previous count");
	}

	write_nt_success(emulator);
}

// NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
static void handle_resume_thread(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type thread_handle, emulator_t::address_type previous_count_ptr)
{
	THREAD_LOG("NtResumeThread called (handle=0x{:X}, previous=0x{:X}) - stub",
		thread_handle, previous_count_ptr);

	if (previous_count_ptr)
	{
		const std::uint32_t previous = 0;
		emulator_err_t error = emulator->write_virtual_memory(previous_count_ptr, &previous, sizeof(previous));
		error.throw_if("NtResumeThread: write previous count");
	}

	write_nt_success(emulator);
}

// NtGetContextThread(HANDLE ThreadHandle, PCONTEXT Context)
static void handle_get_context_thread(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type thread_handle, emulator_t::address_type context_ptr)
{
	THREAD_LOG("NtGetContextThread called (handle=0x{:X}, context=0x{:X})",
		thread_handle, context_ptr);

	if (!context_ptr)
	{
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	CONTEXT ctx = {};
	emulator_err_t error = emulator->read_virtual_memory(context_ptr, &ctx, sizeof(ctx));
	error.throw_if("NtGetContextThread: read context flags");

	const auto flags = ctx.ContextFlags;
	const bool is_current = (thread_handle == static_cast<emulator_t::address_type>(-2));

	const thread_state_t* state = nullptr;

	if (is_current && kernel::current_thread)
	{
		state = &kernel::current_thread->state();
	}
	else
	{
		const auto thread_obj = kernel::active_handle_table().get_object_from_handle<thread_object_t>(thread_handle);
		if (thread_obj && thread_obj->thread)
		{
			state = &thread_obj->thread->state();
		}
	}

	if (!state)
	{
		// fill with current register state for current thread
		ctx.ContextFlags = flags;

		if (flags & 0x00100002) // CONTEXT_INTEGER
		{
			ctx.Rax = emulator->read_register<x86::reg::rax, std::uint64_t>();
			ctx.Rbx = emulator->read_register<x86::reg::rbx, std::uint64_t>();
			ctx.Rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			ctx.Rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();
			ctx.Rsi = emulator->read_register<x86::reg::rsi, std::uint64_t>();
			ctx.Rdi = emulator->read_register<x86::reg::rdi, std::uint64_t>();
			ctx.R8 = emulator->read_register<x86::reg::r8, std::uint64_t>();
			ctx.R9 = emulator->read_register<x86::reg::r9, std::uint64_t>();
			ctx.R10 = emulator->read_register<x86::reg::r10, std::uint64_t>();
			ctx.R11 = emulator->read_register<x86::reg::r11, std::uint64_t>();
			ctx.R12 = emulator->read_register<x86::reg::r12, std::uint64_t>();
			ctx.R13 = emulator->read_register<x86::reg::r13, std::uint64_t>();
			ctx.R14 = emulator->read_register<x86::reg::r14, std::uint64_t>();
			ctx.R15 = emulator->read_register<x86::reg::r15, std::uint64_t>();
		}

		if (flags & 0x00100001) // CONTEXT_CONTROL
		{
			ctx.Rsp = emulator->read_register<x86::reg::rsp, std::uint64_t>();
			ctx.Rbp = emulator->read_register<x86::reg::rbp, std::uint64_t>();
			ctx.Rip = emulator->read_register<x86::reg::rip, std::uint64_t>();
			ctx.EFlags = static_cast<std::uint32_t>(emulator->read_register<x86::reg::rflags, std::uint64_t>());
		}

		error = emulator->write_virtual_memory(context_ptr, &ctx, sizeof(ctx));
		error.throw_if("NtGetContextThread: write context");
		write_nt_success(emulator);
		return;
	}

	ctx.ContextFlags = flags;

	if (flags & 0x00100002) // CONTEXT_INTEGER
	{
		ctx.Rax = state->rax;
		ctx.Rbx = state->rbx;
		ctx.Rcx = state->rcx;
		ctx.Rdx = state->rdx;
		ctx.Rsi = state->rsi;
		ctx.Rdi = state->rdi;
		ctx.R8 = state->r8;
		ctx.R9 = state->r9;
		ctx.R10 = state->r10;
		ctx.R11 = state->r11;
		ctx.R12 = state->r12;
		ctx.R13 = state->r13;
		ctx.R14 = state->r14;
		ctx.R15 = state->r15;
	}

	if (flags & 0x00100001) // CONTEXT_CONTROL
	{
		ctx.Rsp = state->rsp;
		ctx.Rbp = state->rbp;
		ctx.Rip = state->rip;
		ctx.EFlags = static_cast<std::uint32_t>(state->rflags);
	}

	error = emulator->write_virtual_memory(context_ptr, &ctx, sizeof(ctx));
	error.throw_if("NtGetContextThread: write context");

	THREAD_LOG("NtGetContextThread: filled context (flags=0x{:X})", flags);
	write_nt_success(emulator);
}

// NtSetContextThread(HANDLE ThreadHandle, PCONTEXT Context)
static void handle_set_context_thread(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type thread_handle, emulator_t::address_type context_ptr)
{
	THREAD_LOG("NtSetContextThread called (handle=0x{:X}, context=0x{:X}) - stub",
		thread_handle, context_ptr);

	write_nt_success(emulator);
}

// NtAlertThreadByThreadId(HANDLE ThreadId)
static void handle_alert_thread_by_id(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type thread_id)
{
	THREAD_LOG("NtAlertThreadByThreadId called (tid=0x{:X})", thread_id);

	write_nt_success(emulator);
}

// NtWaitForAlertByThreadId(PVOID Address, PLARGE_INTEGER Timeout)
static void handle_wait_for_alert_by_id(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type address, emulator_t::address_type timeout_ptr)
{
	std::int64_t timeout_value = 0;
	bool has_timeout = false;

	if (timeout_ptr)
	{
		has_timeout = true;
		emulator_err_t error = emulator->read_virtual_memory(timeout_ptr, &timeout_value, sizeof(timeout_value));
		error.throw_if("NtWaitForAlertByThreadId: read timeout");
	}

	THREAD_LOG("NtWaitForAlertByThreadId called (addr=0x{:X}, timeout={})",
		address, has_timeout ? timeout_value : -1);

	// single-threaded - alert always arrives immediately
	write_nt_success(emulator);
}

// NtOpenThreadToken(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, PHANDLE TokenHandle)
static void handle_open_thread_token(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type thread_handle, std::uint32_t desired_access,
	std::uint32_t open_as_self, emulator_t::address_type token_handle_ptr)
{
	THREAD_LOG("NtOpenThreadToken called (handle=0x{:X}, access=0x{:X}, self={}) -> STATUS_NO_TOKEN",
		thread_handle, desired_access, open_as_self);

	write_nt_status(emulator, status_no_token);
}

// NtOpenThreadTokenEx(HANDLE ThreadHandle, ACCESS_MASK DesiredAccess, BOOLEAN OpenAsSelf, ULONG HandleAttributes, PHANDLE TokenHandle)
static void handle_open_thread_token_ex(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type thread_handle, std::uint32_t desired_access,
	std::uint32_t open_as_self, std::uint32_t handle_attributes,
	emulator_t::address_type token_handle_ptr)
{
	THREAD_LOG("NtOpenThreadTokenEx called (handle=0x{:X}, access=0x{:X}, self={}, attrs=0x{:X}) -> STATUS_NO_TOKEN",
		thread_handle, desired_access, open_as_self, handle_attributes);

	write_nt_status(emulator, status_no_token);
}

// NtGetCurrentProcessorNumber()
static void handle_get_current_processor_number(const std::shared_ptr<emulator_t>& emulator)
{
	THREAD_LOG("NtGetCurrentProcessorNumber called -> 0");

	write_return_value(emulator, static_cast<std::uint32_t>(0));
}

// NtGetCurrentProcessorNumberEx(PPROCESSOR_NUMBER ProcNumber)
static void handle_get_current_processor_number_ex(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type proc_number_ptr)
{
	THREAD_LOG("NtGetCurrentProcessorNumberEx called (out=0x{:X})", proc_number_ptr);

	if (proc_number_ptr)
	{
		// PROCESSOR_NUMBER: { Group (USHORT), Number (UCHAR), Reserved (UCHAR) }
		std::uint32_t proc_number = 0; // group=0, number=0, reserved=0
		emulator_err_t error = emulator->write_virtual_memory(proc_number_ptr, &proc_number, sizeof(proc_number));
		error.throw_if("NtGetCurrentProcessorNumberEx: write proc number");
	}

	write_nt_success(emulator);
}

static void handle_create_thread_ex(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type thread_handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes, std::uint64_t process_handle,
	emulator_t::address_type start_routine, emulator_t::address_type argument,
	std::uint32_t create_flags, std::uint64_t zero_bits,
	std::uint64_t stack_size, std::uint64_t maximum_stack_size,
	emulator_t::address_type attribute_list)
{

	THREAD_LOG("NtCreateThreadEx called (handle_out=0x{:X}, start=0x{:X}, arg=0x{:X}, flags=0x{:X}, stack_size=0x{:X})",
		thread_handle_out, start_routine, argument, create_flags, stack_size);

	if ((create_flags & 0xFFFFFF80) != 0)
	{
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	const bool create_suspended = (create_flags & 1) != 0;
	const bool is_usermode = kernel::current_thread && kernel::current_thread->state().is_usermode;

	emulator_t::address_type teb_address = 0;
	emulator_t::address_type stack_base = 0;

	if (is_usermode && user::memory_manager)
	{
		constexpr emulator_t::size_type default_stack_size = 0x10000;
		const auto actual_stack_size = stack_size > 0 ? stack_size : default_stack_size;
		const auto aligned_stack_size = (actual_stack_size + 0xFFF) & ~static_cast<emulator_t::size_type>(0xFFF);

		const auto stack_alloc = user::memory_manager->allocate_pages(aligned_stack_size);

		if (!stack_alloc)
		{
			THREAD_ERR_LOG("NtCreateThreadEx: failed to allocate stack (0x{:X} bytes)", aligned_stack_size);
			write_nt_status(emulator, 0xC000009A); // STATUS_INSUFFICIENT_RESOURCES
			return;
		}

		stack_base = stack_alloc + aligned_stack_size;

		const auto teb_alloc = user::memory_manager->allocate_pages(user::teb64_alloc_size);

		if (!teb_alloc)
		{
			THREAD_ERR_LOG("NtCreateThreadEx: failed to allocate TEB");
			write_nt_status(emulator, 0xC000009A);
			return;
		}

		teb_address = teb_alloc;

		user::teb64_t teb{};
		teb.NtTib.StackBase = stack_base;
		teb.NtTib.StackLimit = stack_alloc;
		teb.NtTib.Self = teb_address;

		if (kernel::current_thread)
		{
			teb.ClientId.UniqueProcess = kernel::current_thread->process()->id();
		}

		teb.ProcessEnvironmentBlock = kernel::active_process()->peb_address();

		static_cast<void>(emulator->write_virtual_memory(teb_address, &teb, sizeof(teb)));

		constexpr std::uint8_t skip_nls_cache = 1;
		static_cast<void>(emulator->write_virtual_memory(
			teb_address + 0x179C, &skip_nls_cache, sizeof(skip_nls_cache)));
	}

	const std::uint64_t args[] = { argument };
	auto thread = kernel::create_thread_at(emulator, start_routine, args, stack_base, teb_address);

	if (!create_suspended)
	{
		kernel::pending_threads.push(thread);
	}

	kernel::object_manager->register_object(thread->address(), std::make_shared<thread_object_t>(thread));
	const auto handle_value = kernel::active_handle_table().create_handle(thread->address(), desired_access);

	if (thread_handle_out)
	{
		emulator_err_t error = emulator->write_virtual_memory(thread_handle_out, &handle_value, sizeof(handle_value));
		error.throw_if("NtCreateThreadEx: write handle");
	}

	// write back TEB and ClientId through the attribute list if provided
	if (attribute_list)
	{
		std::uint64_t total_length = 0;
		static_cast<void>(emulator->read_virtual_memory(attribute_list, &total_length, sizeof(total_length)));

		// PS_ATTRIBUTE_LIST: TotalLength (SIZE_T on x64 = 8 bytes), then array of PS_ATTRIBUTE entries
		// each PS_ATTRIBUTE is: Attribute (ULONG_PTR), Size (SIZE_T), Value (union), ReturnLength (PSIZE_T)
		constexpr std::uint64_t ps_attribute_client_id = 0x10003;
		constexpr std::uint64_t ps_attribute_teb_address = 0x10004;
		constexpr std::size_t ps_attribute_size = 32; // sizeof(PS_ATTRIBUTE) on x64
		constexpr std::size_t total_length_size = 8; // sizeof(SIZE_T) on x64

		if (total_length > total_length_size)
		{
			const auto entry_count = (total_length - total_length_size) / ps_attribute_size;

			for (std::size_t i = 0; i < entry_count && i < 16; ++i)
			{
				const auto entry_offset = attribute_list + total_length_size + (i * ps_attribute_size);

				std::uint64_t attr_id = 0;
				static_cast<void>(emulator->read_virtual_memory(entry_offset, &attr_id, sizeof(attr_id)));

				std::uint64_t attr_value = 0;
				static_cast<void>(emulator->read_virtual_memory(entry_offset + 16, &attr_value, sizeof(attr_value)));

				if (attr_id == ps_attribute_client_id && attr_value)
				{
					const std::uint64_t cid[2] = {
						kernel::current_thread ? kernel::current_thread->process()->id() : 0,
						thread->id()
					};
					static_cast<void>(emulator->write_virtual_memory(attr_value, &cid, sizeof(cid)));
				}
				else if (attr_id == ps_attribute_teb_address && attr_value)
				{
					static_cast<void>(emulator->write_virtual_memory(attr_value, &teb_address, sizeof(teb_address)));
				}
			}
		}
	}

	THREAD_LOG("NtCreateThreadEx: created tid={} handle=0x{:X} (start=0x{:X}, suspended={}, usermode={}, teb=0x{:X})",
		thread->id(), handle_value, start_routine, create_suspended, is_usermode, teb_address);

	write_nt_success(emulator);
}

void redirect_ntoskrnl_thread_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_create_thread_ex>(emulator, mapped_image, "NtCreateThreadEx");
	redirect_handler<handle_create_thread_ex>(emulator, mapped_image, "ZwCreateThreadEx");

	redirect_handler<handle_delay_execution>(emulator, mapped_image, "NtDelayExecution");
	redirect_handler<handle_delay_execution>(emulator, mapped_image, "ZwDelayExecution");

	redirect_handler<handle_terminate_thread>(emulator, mapped_image, "NtTerminateThread");
	redirect_handler<handle_terminate_thread>(emulator, mapped_image, "ZwTerminateThread");

	redirect_handler<handle_open_thread>(emulator, mapped_image, "NtOpenThread");
	redirect_handler<handle_open_thread>(emulator, mapped_image, "ZwOpenThread");

	redirect_handler<handle_suspend_thread>(emulator, mapped_image, "NtSuspendThread");
	redirect_handler<handle_suspend_thread>(emulator, mapped_image, "ZwSuspendThread");

	redirect_handler<handle_resume_thread>(emulator, mapped_image, "NtResumeThread");
	redirect_handler<handle_resume_thread>(emulator, mapped_image, "ZwResumeThread");

	redirect_handler<handle_get_context_thread>(emulator, mapped_image, "NtGetContextThread");
	redirect_handler<handle_get_context_thread>(emulator, mapped_image, "ZwGetContextThread");

	redirect_handler<handle_set_context_thread>(emulator, mapped_image, "NtSetContextThread");
	redirect_handler<handle_set_context_thread>(emulator, mapped_image, "ZwSetContextThread");

	redirect_handler<handle_alert_thread_by_id>(emulator, mapped_image, "NtAlertThreadByThreadId");
	redirect_handler<handle_alert_thread_by_id>(emulator, mapped_image, "ZwAlertThreadByThreadId");

	redirect_handler<handle_wait_for_alert_by_id>(emulator, mapped_image, "NtWaitForAlertByThreadId");
	redirect_handler<handle_wait_for_alert_by_id>(emulator, mapped_image, "ZwWaitForAlertByThreadId");

	redirect_handler<handle_open_thread_token>(emulator, mapped_image, "NtOpenThreadToken");
	redirect_handler<handle_open_thread_token>(emulator, mapped_image, "ZwOpenThreadToken");

	redirect_handler<handle_open_thread_token_ex>(emulator, mapped_image, "NtOpenThreadTokenEx");
	redirect_handler<handle_open_thread_token_ex>(emulator, mapped_image, "ZwOpenThreadTokenEx");

	redirect_handler<handle_get_current_processor_number>(emulator, mapped_image, "NtGetCurrentProcessorNumber");
	redirect_handler<handle_get_current_processor_number>(emulator, mapped_image, "ZwGetCurrentProcessorNumber");

	redirect_handler<handle_get_current_processor_number_ex>(emulator, mapped_image, "NtGetCurrentProcessorNumberEx");
	redirect_handler<handle_get_current_processor_number_ex>(emulator, mapped_image, "ZwGetCurrentProcessorNumberEx");
}
