#include "nt_helpers.hpp"
#include "../../kernel/exception.hpp"

static std::uint8_t get_guest_irql(const std::shared_ptr<emulator_t>& emulator)
{
	return emulator->read_register<x86::reg::cr8, std::uint8_t>();
}

void redirect_ntoskrnl_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	// todo: actually register callbacks into a list and invoke on bugcheck
	redirect_function(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rdx = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto r8 = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto r9 = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			std::string component_name;

			if (r9)
			{
				component_name = kernel::read_guest_string(*emulator, r9);
			}

			spdlog::info("KeRegisterBugCheckReasonCallback called (record=0x{:X}, routine=0x{:X}, reason=0x{:X}, component='{}')",
				rcx, rdx, r8, component_name);

			write_return_value(emulator, 1);
		},
		mapped_image,
		"KeRegisterBugCheckReasonCallback"
	);

	// todo: actually deregister callbacks from the list
	redirect_function(
		[emulator]
		{
			const auto record = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			spdlog::info("KeDeregisterBugCheckReasonCallback called (record=0x{:X})", record);

			write_return_value(emulator, 1);
		},
		mapped_image,
		"KeDeregisterBugCheckReasonCallback"
	);

	redirect_function(
		[emulator]
		{
			const auto irql = get_guest_irql(emulator);
			const bool result = irql != 0;

			spdlog::info("KeAreAllApcsDisabled called (irql={}, result={})", irql, result);

			write_return_value(emulator, result);
		},
		mapped_image,
		"KeAreAllApcsDisabled"
	);

	redirect_function(
		[emulator]
		{
			const auto irql = get_guest_irql(emulator);

			spdlog::info("KeGetCurrentIrql called (irql={})", irql);

			write_return_value(emulator, irql);
		},
		mapped_image,
		"KeGetCurrentIrql"
	);

	redirect_function(
		[emulator]
		{
			const auto event_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto type = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto state = emulator->read_register<x86::reg::r8, std::uint8_t>();

			spdlog::info("KeInitializeEvent called (event=0x{:X}, type={}, state={})",
				event_address, type, state);

			const auto signal_state = static_cast<std::int32_t>(state);
			emulator_err_t error = emulator->write_virtual_memory(
				event_address + offsetof(_KEVENT, Header.SignalState), &signal_state, sizeof(signal_state));
			error.throw_if("KeInitializeEvent: write SignalState");

			const auto wait_list_head_address = event_address + offsetof(_KEVENT, Header.WaitListHead);
			const std::uint64_t wait_list_pointers[2] = { wait_list_head_address, wait_list_head_address };
			error = emulator->write_virtual_memory(wait_list_head_address, &wait_list_pointers, sizeof(wait_list_pointers));
			error.throw_if("KeInitializeEvent: write WaitListHead");

			const auto event_type = static_cast<std::uint8_t>(type);
			error = emulator->write_virtual_memory(
				event_address + offsetof(_KEVENT, Header.Type), &event_type, sizeof(event_type));
			error.throw_if("KeInitializeEvent: write Type");

			constexpr std::uint16_t size_word = 1536;
			error = emulator->write_virtual_memory(event_address + 1, &size_word, sizeof(size_word));
			error.throw_if("KeInitializeEvent: write header size word");
		},
		mapped_image,
		"KeInitializeEvent"
	);

	redirect_function(
		[emulator]
		{
			const auto timer_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			spdlog::info("KeInitializeTimer called (timer=0x{:X})", timer_address);

			constexpr std::uint64_t zero_qword = 0;
			emulator_err_t error = emulator->write_virtual_memory(
				timer_address + offsetof(_KTIMER, Header.Lock), &zero_qword, sizeof(zero_qword));
			error.throw_if("KeInitializeTimer: zero Lock+SignalState");

			constexpr std::uint8_t timer_type = 8;
			error = emulator->write_virtual_memory(
				timer_address + offsetof(_KTIMER, Header.Type), &timer_type, sizeof(timer_type));
			error.throw_if("KeInitializeTimer: write Type");

			const auto wait_list_head_address = timer_address + offsetof(_KTIMER, Header.WaitListHead);
			const std::uint64_t wait_list_pointers[2] = { wait_list_head_address, wait_list_head_address };
			error = emulator->write_virtual_memory(wait_list_head_address, &wait_list_pointers, sizeof(wait_list_pointers));
			error.throw_if("KeInitializeTimer: write WaitListHead");

			constexpr std::uint64_t zero_due_time = 0;
			error = emulator->write_virtual_memory(
				timer_address + offsetof(_KTIMER, DueTime), &zero_due_time, sizeof(zero_due_time));
			error.throw_if("KeInitializeTimer: zero DueTime");

			constexpr std::uint32_t zero_period = 0;
			error = emulator->write_virtual_memory(
				timer_address + offsetof(_KTIMER, Period), &zero_period, sizeof(zero_period));
			error.throw_if("KeInitializeTimer: zero Period");

			constexpr std::uint32_t zero_processor = 0;
			error = emulator->write_virtual_memory(
				timer_address + offsetof(_KTIMER, Processor), &zero_processor, sizeof(zero_processor));
			error.throw_if("KeInitializeTimer: zero Processor");
		},
		mapped_image,
		"KeInitializeTimer"
	);

	// todo: actually insert timer into a timer queue and fire dpc when due
	redirect_function(
		[emulator]
		{
			const auto timer_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto due_time = emulator->read_register<x86::reg::rdx, std::int64_t>();
			const auto dpc = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			spdlog::info("KeSetTimer called (timer=0x{:X}, due_time={}, dpc=0x{:X})",
				timer_address, due_time, dpc);

			emulator_err_t error = emulator->write_virtual_memory(
				timer_address + offsetof(_KTIMER, DueTime), &due_time, sizeof(due_time));
			error.throw_if("KeSetTimer: write DueTime");

			error = emulator->write_virtual_memory(
				timer_address + offsetof(_KTIMER, Dpc), &dpc, sizeof(dpc));
			error.throw_if("KeSetTimer: write Dpc");

			constexpr std::int32_t zero_period = 0;
			error = emulator->write_virtual_memory(
				timer_address + offsetof(_KTIMER, Period), &zero_period, sizeof(zero_period));
			error.throw_if("KeSetTimer: write Period");

			write_return_value(emulator, 0);
		},
		mapped_image,
		"KeSetTimer"
	);

	// todo: actually track callback registrations and fire them on relevant events
	redirect_function(
		[emulator]
		{
			const auto callback_object_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto object_attributes_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto create = emulator->read_register<x86::reg::r8, std::uint8_t>();
			const auto allow_multiple = emulator->read_register<x86::reg::r9, std::uint8_t>();

			std::string object_name;

			if (object_attributes_address)
			{
				auto oa = emulator_object_t<OBJECT_ATTRIBUTES>::view_at(emulator, object_attributes_address).read();
				const auto name_address = reinterpret_cast<emulator_t::address_type>(oa.ObjectName);

				if (name_address)
				{
					const auto us = emulator_object_t<UNICODE_STRING>::view_at(emulator, name_address).read();
					const auto buffer_address = reinterpret_cast<emulator_t::address_type>(us.Buffer);

					if (buffer_address && us.Length)
					{
						object_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
					}
				}
			}

			spdlog::info("ExCreateCallback called (out=0x{:X}, name='{}', create={}, allow_multiple={})",
				callback_object_out, object_name, create, allow_multiple);

			if (!create && object_name.empty())
			{
				spdlog::warn("ExCreateCallback: no name and Create=FALSE, returning STATUS_UNSUCCESSFUL");
				write_nt_status(emulator, 0xC0000001);
				return;
			}

			constexpr std::size_t callback_object_size = 0x38;
			const auto allocation = emulator->heap_allocate(callback_object_size, prot_read_write);

			if (!allocation)
			{
				spdlog::error("ExCreateCallback: heap allocation failed");
				write_nt_status(emulator, 0xC000009A);
				return;
			}

			const auto object_address = *allocation;

			constexpr std::uint32_t signature = 0x6C6C6143;
			emulator_err_t error = emulator->write_virtual_memory(object_address, &signature, sizeof(signature));
			error.throw_if("ExCreateCallback: write signature");

			constexpr std::uint64_t zero = 0;
			error = emulator->write_virtual_memory(object_address + 0x08, &zero, sizeof(zero));
			error.throw_if("ExCreateCallback: zero field at +0x08");

			const auto list_head_address = object_address + 0x10;
			const std::uint64_t list_pointers[2] = { list_head_address, list_head_address };
			error = emulator->write_virtual_memory(list_head_address, &list_pointers, sizeof(list_pointers));
			error.throw_if("ExCreateCallback: write RegisteredCallbacks list head");

			error = emulator->write_virtual_memory(object_address + 0x20, &allow_multiple, sizeof(allow_multiple));
			error.throw_if("ExCreateCallback: write AllowMultipleCallbacks");

			error = emulator->write_virtual_memory(callback_object_out, &object_address, sizeof(object_address));
			error.throw_if("ExCreateCallback: write output pointer");

			spdlog::info("ExCreateCallback: allocated callback object at 0x{:X}", object_address);

			write_nt_success(emulator);
		},
		mapped_image,
		"ExCreateCallback"
	);

	// todo: actually register the callback and invoke it on events
	redirect_function(
		[emulator]
		{
			const auto callback_object = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto callback_function = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto callback_context = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			spdlog::info("ExRegisterCallback called (object=0x{:X}, function=0x{:X}, context=0x{:X})",
				callback_object, callback_function, callback_context);

			const auto handle = emulator->heap_allocate(8, prot_read_write, true);
			emulator_err_t error = handle.error_or({});
			error.throw_if("allocate ExRegisterCallback handle");

			write_return_value(emulator, *handle);
		},
		mapped_image,
		"ExRegisterCallback"
	);

	// todo: wake waiting threads when signalstate transitions from 0 to 1
	redirect_function(
		[emulator]
		{
			const auto event_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto increment = emulator->read_register<x86::reg::rdx, std::int32_t>();
			const auto wait = emulator->read_register<x86::reg::r8, std::uint8_t>();

			std::int32_t previous_state = 0;

			emulator_err_t error = emulator->read_virtual_memory(
				event_address + offsetof(_KEVENT, Header.SignalState), &previous_state, sizeof(previous_state));
			error.throw_if("KeSetEvent: read SignalState");

			constexpr std::int32_t signaled = 1;

			error = emulator->write_virtual_memory(
				event_address + offsetof(_KEVENT, Header.SignalState), &signaled, sizeof(signaled));
			error.throw_if("KeSetEvent: write SignalState");

			spdlog::info("KeSetEvent called (event=0x{:X}, increment={}, wait={}, previous_state={})",
				event_address, increment, wait, previous_state);

			write_return_value(emulator, static_cast<std::uint32_t>(previous_state));
		},
		mapped_image,
		"KeSetEvent"
	);

	// todo: implement debug prompt interaction
	redirect_function(
		kernel::function_implementation_t([emulator](bool& skip_return)
		{
			const auto prompt_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto response_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto length = emulator->read_register<x86::reg::r8, std::uint32_t>();

			std::string prompt;

			if (prompt_address)
			{
				prompt = kernel::read_guest_string(*emulator, prompt_address);
			}

			spdlog::info("DbgPrompt called (prompt='{}', response=0x{:X}, length={})",
				prompt, response_address, length);

			const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

			kernel::handle_exception(emulator, rip, 0, 0);
			skip_return = true;
		}),
		mapped_image,
		"DbgPrompt"
	);

	redirect_function(
		[emulator]
		{
			const auto broadcast_function = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto context = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			spdlog::info("KeIpiGenericCall called (broadcast_function=0x{:X}, context=0x{:X})",
				broadcast_function, context);

			const auto saved_rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			constexpr std::size_t shadow_space = 0x20 + 8;
			const auto call_stack = emulator->heap_allocate(shadow_space, prot_read_write, true);
			emulator_err_t error = call_stack.error_or({});
			error.throw_if("allocate KeIpiGenericCall stack");

			emulator->write_register<x86::reg::rcx>(context);
			emulator->write_register<x86::reg::rsp>(*call_stack + shadow_space);

			spdlog::info("KeIpiGenericCall: invoking guest BroadcastFunction at 0x{:X} with context=0x{:X}",
				broadcast_function, context);

			const auto run_result = emulator->run_at(broadcast_function, emulator_t::thread_return_address);

			if (!run_result)
			{
				spdlog::error("KeIpiGenericCall: run guest callback: 'failed'");
			}

			emulator->write_register<x86::reg::rsp>(saved_rsp);

			const auto result = emulator->read_register<x86::reg::rax, std::uint64_t>();

			spdlog::info("KeIpiGenericCall: guest callback returned 0x{:X}", result);

			write_return_value(emulator, result);
		},
		mapped_image,
		"KeIpiGenericCall"
	);

	// todo: actually track and unregister load image notify callbacks
	redirect_function(
		[emulator]
		{
			const auto routine = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			spdlog::info("PsRemoveLoadImageNotifyRoutine called (routine=0x{:X})", routine);

			write_nt_success(emulator);
		},
		mapped_image,
		"PsRemoveLoadImageNotifyRoutine"
	);

	// todo: actually track and unregister create thread notify callbacks
	redirect_function(
		[emulator]
		{
			const auto routine = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			spdlog::info("PsRemoveCreateThreadNotifyRoutine called (routine=0x{:X})", routine);

			write_nt_success(emulator);
		},
		mapped_image,
		"PsRemoveCreateThreadNotifyRoutine"
	);

	// todo: actually track process creation notify callbacks
	redirect_function(
		[emulator]
		{
			const auto routine = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto remove = emulator->read_register<x86::reg::rdx, std::uint8_t>();

			spdlog::info("PsSetCreateProcessNotifyRoutine called (routine=0x{:X}, remove={})", routine, remove);

			write_nt_success(emulator);
		},
		mapped_image,
		"PsSetCreateProcessNotifyRoutine"
	);

	redirect_function(
		[emulator]
		{
			const auto routine = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto remove = emulator->read_register<x86::reg::rdx, std::uint8_t>();

			spdlog::info("PsSetCreateProcessNotifyRoutineEx called (routine=0x{:X}, remove={})", routine, remove);

			write_nt_success(emulator);
		},
		mapped_image,
		"PsSetCreateProcessNotifyRoutineEx"
	);

	redirect_function(
		[emulator]
		{
			const auto spin_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			const auto old_irql = get_guest_irql(emulator);

			constexpr std::uint64_t dispatch_level = 2;
			emulator->write_register<x86::reg::cr8>(dispatch_level);

			spdlog::info("KeAcquireSpinLockRaiseToDpc called (spin_lock=0x{:X}, old_irql={})", spin_lock, old_irql);

			write_return_value(emulator, old_irql);
		},
		mapped_image,
		"KeAcquireSpinLockRaiseToDpc"
	);

	redirect_function(
		[emulator]
		{
			const auto spin_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto new_irql = emulator->read_register<x86::reg::rdx, std::uint8_t>();

			spdlog::info("KeReleaseSpinLock called (spin_lock=0x{:X}, new_irql={})", spin_lock, new_irql);

			emulator->write_register<x86::reg::cr8>(static_cast<std::uint64_t>(new_irql));
		},
		mapped_image,
		"KeReleaseSpinLock"
	);

	// todo: actually wait for rundown protection references to drain
	redirect_function(
		[emulator]
		{
			const auto run_ref = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			spdlog::info("ExWaitForRundownProtectionRelease called (run_ref=0x{:X})", run_ref);

			constexpr std::uint64_t rundown_complete = 1;
			emulator_err_t error = emulator->write_virtual_memory(run_ref, &rundown_complete, sizeof(rundown_complete));
			error.throw_if("ExWaitForRundownProtectionRelease: write rundown value");
		},
		mapped_image,
		"ExWaitForRundownProtectionRelease"
	);

	// todo: advance guest clock time when delaying execution
	redirect_function(
		[emulator]
		{
			const auto wait_mode = emulator->read_register<x86::reg::rcx, std::uint8_t>();
			const auto alertable = emulator->read_register<x86::reg::rdx, std::uint8_t>();
			const auto interval_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			std::int64_t interval = 0;

			if (interval_address)
			{
				emulator_err_t error = emulator->read_virtual_memory(interval_address, &interval, sizeof(interval));
				error.throw_if("KeDelayExecutionThread: read interval");
			}

			spdlog::info("KeDelayExecutionThread called (wait_mode={}, alertable={}, interval={})",
				wait_mode, alertable, interval);

			write_nt_success(emulator);
		},
		mapped_image,
		"KeDelayExecutionThread"
	);

	// todo: actually remove timer from timer queue
	redirect_function(
		[emulator]
		{
			const auto timer_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			std::int64_t due_time = 0;

			emulator_err_t error = emulator->read_virtual_memory(
				timer_address + offsetof(_KTIMER, DueTime), &due_time, sizeof(due_time));
			error.throw_if("KeCancelTimer: read DueTime");

			const auto was_set = due_time != 0;

			constexpr std::int64_t zero_due_time = 0;
			error = emulator->write_virtual_memory(
				timer_address + offsetof(_KTIMER, DueTime), &zero_due_time, sizeof(zero_due_time));
			error.throw_if("KeCancelTimer: zero DueTime");

			spdlog::info("KeCancelTimer called (timer=0x{:X}, was_set={})", timer_address, was_set);

			write_return_value(emulator, was_set);
		},
		mapped_image,
		"KeCancelTimer"
	);

	// todo: actually dereference the adapter object
	redirect_function(
		[emulator]
		{
			const auto adapter = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			spdlog::info("HalPutDmaAdapter called (adapter=0x{:X})", adapter);
		},
		mapped_image,
		"HalPutDmaAdapter"
	);

	redirect_function(
		[emulator](bool& skip_return)
		{
			const auto exception_record_addr = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto establisher_frame = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto context_record_addr = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto dispatcher_context_addr = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			EXCEPTION_RECORD record = { };
			emulator_err_t error = emulator->read_virtual_memory(exception_record_addr, &record, sizeof(record));
			error.throw_if("__C_specific_handler: read exception record");

			DISPATCHER_CONTEXT dispatch = { };
			error = emulator->read_virtual_memory(dispatcher_context_addr, &dispatch, sizeof(dispatch));
			error.throw_if("__C_specific_handler: read dispatcher context");

			const auto image_base = dispatch.ImageBase;
			const auto control_pc = dispatch.ControlPc;
			const auto control_pc_rva = static_cast<std::uint32_t>(control_pc - image_base);
			const auto handler_data = reinterpret_cast<emulator_t::address_type>(dispatch.HandlerData);
			const auto scope_index = dispatch.ScopeIndex;

			const auto handler_module = kernel::find_module_from_rip(control_pc);

			if (!handler_module)
			{
				spdlog::error("__C_specific_handler: module not found for control_pc 0x{:X}", control_pc);
				write_return_value(emulator, 1);
				return;
			}

			const auto buf = handler_module->buffer();
			const auto module_base = buf.data();

			const auto handler_data_rva = static_cast<std::uint32_t>(handler_data - image_base);
			const auto* scope_table_ptr = reinterpret_cast<const std::uint32_t*>(module_base + handler_data_rva);
			const auto scope_count = scope_table_ptr[0];

			struct scope_entry_t
			{
				std::uint32_t begin_address;
				std::uint32_t end_address;
				std::uint32_t handler_address;
				std::uint32_t jump_target;
			};

			const auto* scopes = reinterpret_cast<const scope_entry_t*>(&scope_table_ptr[1]);

			spdlog::info("__C_specific_handler: control_pc_rva=0x{:X}, flags=0x{:X}, scope_count={}, scope_index={}",
				control_pc_rva, record.ExceptionFlags, scope_count, scope_index);

			if ((record.ExceptionFlags & 0x66) != 0)
			{
				// todo: unwind case
				spdlog::info("__C_specific_handler: unwind case (flags=0x{:X}), returning continue_search",
					record.ExceptionFlags);
				write_return_value(emulator, 1);
				return;
			}

			for (std::uint32_t i = scope_index; i < scope_count; ++i)
			{
				const auto& scope = scopes[i];

				if (control_pc_rva < scope.begin_address || control_pc_rva >= scope.end_address)
				{
					continue;
				}

				if (!scope.jump_target)
				{
					continue;
				}

				spdlog::info("__C_specific_handler: scope[{}] begin=0x{:X} end=0x{:X} handler=0x{:X} target=0x{:X}",
					i, scope.begin_address, scope.end_address, scope.handler_address, scope.jump_target);

				if (scope.handler_address == 1)
				{
					const auto target = image_base + scope.jump_target;

					spdlog::info("__C_specific_handler: EXCEPTION_EXECUTE_HANDLER, target=0x{:X}", target);

					emulator->write_register<x86::reg::rip>(target);
					emulator->write_register<x86::reg::rsp>(establisher_frame);
					skip_return = true;

					return;
				}

				const auto filter_address = image_base + scope.handler_address;

				constexpr std::size_t pointers_size = 16;
				const auto pointers_alloc = emulator->heap_allocate(pointers_size + 0x20, prot_read_write, true);
				error = pointers_alloc.error_or({});
				error.throw_if("__C_specific_handler: allocate exception pointers");

				const auto pointers_address = *pointers_alloc + 0x20;
				const std::uint64_t exception_pointers[2] = { exception_record_addr, context_record_addr };
				error = emulator->write_virtual_memory(pointers_address, &exception_pointers, sizeof(exception_pointers));
				error.throw_if("__C_specific_handler: write exception pointers");

				const auto saved_rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();
				const auto saved_rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();
				const auto saved_rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
				const auto saved_rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				emulator->write_register<x86::reg::rcx>(pointers_address);
				emulator->write_register<x86::reg::rdx>(establisher_frame);
				emulator->write_register<x86::reg::rsp>(*pointers_alloc);

				spdlog::info("__C_specific_handler: calling filter at 0x{:X}", filter_address);

				const auto run_result = emulator->run_at(filter_address, emulator_t::thread_return_address);
				static_cast<void>(run_result);

				const auto filter_result = emulator->read_register<x86::reg::rax, std::int32_t>();

				emulator->write_register<x86::reg::rcx>(saved_rcx);
				emulator->write_register<x86::reg::rdx>(saved_rdx);
				emulator->write_register<x86::reg::rsp>(saved_rsp);
				emulator->write_register<x86::reg::rip>(saved_rip);

				spdlog::info("__C_specific_handler: filter returned {}", filter_result);

				if (filter_result < 0)
				{
					write_return_value(emulator, 0);
					return;
				}

				if (filter_result > 0)
				{
					const auto target = image_base + scope.jump_target;

					spdlog::info("__C_specific_handler: jumping to __except at 0x{:X}", target);

					emulator->write_register<x86::reg::rip>(target);
					emulator->write_register<x86::reg::rsp>(establisher_frame);
					skip_return = true;

					return;
				}
			}

			spdlog::info("__C_specific_handler: no matching scope, returning continue_search");
			write_return_value(emulator, 1);
		},
		mapped_image,
		"__C_specific_handler"
	);

	redirect_function(
		[emulator]
		{
			const auto thread_address = kernel::current_thread->address();
			const auto process = kernel::current_thread->process();

			// in case ApcState is overwritten, read process directly from thread
			emulator_t::address_type process_address = 0;
			const emulator_err_t error = emulator->read_virtual_memory(
				thread_address + offsetof(_KTHREAD, ApcState) + offsetof(_KAPC_STATE, Process),
				&process_address, sizeof(process_address));

			spdlog::info("PsGetCurrentProcess called (id=0x{:X})", process->id());

			write_return_value(emulator, process_address);
		},
		mapped_image,
		"PsGetCurrentProcess"
	);

	redirect_function(
		kernel::function_implementation_t([emulator](bool& skip_return)
		{
			const auto slist_head = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			if ((slist_head & 0xF) != 0)
			{
				spdlog::warn("InitializeSListHead: unaligned address 0x{:X}, raising STATUS_DATATYPE_MISALIGNMENT", slist_head);

				constexpr std::uint32_t status_datatype_misalignment = 0x80000002;
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				kernel::handle_exception(emulator, rip, status_datatype_misalignment, slist_head);
				skip_return = true;

				return;
			}

			constexpr std::array<std::uint64_t, 2> zero = { 0, 0 };

			emulator_err_t error = emulator->write_virtual_memory(slist_head, zero.data(), sizeof(zero));
			error.throw_if("InitializeSListHead: zero header");

			spdlog::info("InitializeSListHead called (header=0x{:X})", slist_head);
		}),
		mapped_image,
		"InitializeSListHead"
	);

	redirect_function(
		[emulator]
		{
			const auto push_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			constexpr std::uint64_t zero = 0;

			emulator_err_t error = emulator->write_virtual_memory(push_lock, &zero, sizeof(zero));
			error.throw_if("ExInitializePushLock: zero lock");

			spdlog::info("ExInitializePushLock called (lock=0x{:X})", push_lock);
		},
		mapped_image,
		"ExInitializePushLock"
	);

	// todo: actually track load image notify callbacks
	redirect_function(
		[emulator]
		{
			const auto routine = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			spdlog::info("PsSetLoadImageNotifyRoutine called (routine=0x{:X})", routine);

			write_nt_success(emulator);
		},
		mapped_image,
		"PsSetLoadImageNotifyRoutine"
	);

	redirect_function(
		[emulator]
		{
			const auto process_id = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto process_out = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			spdlog::info("PsLookupProcessByProcessId called (pid={}, out=0x{:X})", process_id, process_out);

			for (const auto& process : kernel::process_entries)
			{
				if (process->id() == process_id)
				{
					const auto address = process->address();

					emulator_err_t error = emulator->write_virtual_memory(process_out, &address, sizeof(address));
					error.throw_if("PsLookupProcessByProcessId: write process");

					spdlog::info("PsLookupProcessByProcessId: found process at 0x{:X}", address);

					write_nt_success(emulator);
					return;
				}
			}

			spdlog::warn("PsLookupProcessByProcessId: pid {} not found", process_id);

			constexpr std::uint32_t status_invalid_cid = 0xC000000B;
			write_nt_status(emulator, status_invalid_cid);
		},
		mapped_image,
		"PsLookupProcessByProcessId"
	);

	redirect_function(
		[emulator]
		{
			const auto process_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto image_file_name_address = process_address + offsetof(_EPROCESS, ImageFileName);

			spdlog::info("PsGetProcessImageFileName called (process=0x{:X}) -> 0x{:X}",
				process_address, image_file_name_address);

			write_return_value(emulator, image_file_name_address);
		},
		mapped_image,
		"PsGetProcessImageFileName"
	);

	redirect_function(
		[emulator]
		{
			const auto mutex_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			const auto wait_list_address = mutex_address + offsetof(_FAST_MUTEX, Event) + offsetof(_KEVENT, Header.WaitListHead);

			_FAST_MUTEX mutex = { };

			mutex.Count = 1;
			mutex.Owner = nullptr;
			mutex.Contention = 0;
			mutex.Event.Header.SignalState = 0;
			mutex.Event.Header.WaitListHead.Flink = reinterpret_cast<PLIST_ENTRY>(wait_list_address);
			mutex.Event.Header.WaitListHead.Blink = reinterpret_cast<PLIST_ENTRY>(wait_list_address);
			constexpr std::uint16_t lock_low = 1;
			std::memcpy(const_cast<LONG*>(&mutex.Event.Header.Lock), &lock_low, sizeof(lock_low));
			mutex.Event.Header.Size = 6;

			emulator_err_t error = emulator->write_virtual_memory(mutex_address, &mutex, sizeof(mutex));
			error.throw_if("KeInitializeGuardedMutex: write mutex");

			spdlog::info("KeInitializeGuardedMutex called (mutex=0x{:X})", mutex_address);
		},
		mapped_image,
		"KeInitializeGuardedMutex"
	);

	// todo: actually create and schedule thread
	redirect_function(
		[emulator]
		{
			const auto thread_handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto object_attributes = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto process_handle = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type client_id_out = 0;
			emulator_t::address_type start_routine = 0;
			emulator_t::address_type start_context = 0;

			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &client_id_out, sizeof(client_id_out)));
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &start_routine, sizeof(start_routine)));
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &start_context, sizeof(start_context)));

			spdlog::info("PsCreateSystemThread called (handle_out=0x{:X}, access=0x{:X}, start_routine=0x{:X}, start_context=0x{:X}, process=0x{:X})",
				thread_handle_out, desired_access, start_routine, start_context, process_handle);

			write_nt_success(emulator);
		},
		mapped_image,
		"PsCreateSystemThread"
	);

	redirect_function(
		[emulator]
		{
			const emulator_t::address_type seed_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			const std::uint32_t result = generate_random<std::uint32_t>(0, std::numeric_limits<LONG>::max() - 1);

			emulator_err_t error = emulator->write_virtual_memory(seed_address, &result, sizeof(result));
			error.throw_if("RtlRandomEx: write seed");

			spdlog::info("RtlRandomEx called (seed=0x{:X}) -> 0x{:X}", seed_address, result);

			write_return_value(emulator, result);
		},
		mapped_image,
		"RtlRandomEx"
	);

	// todo: actually track create thread notify callbacks
	redirect_function(
		[emulator]
		{
			const emulator_t::address_type routine = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			spdlog::info("PsSetCreateThreadNotifyRoutine called (routine=0x{:X})", routine);

			write_nt_success(emulator);
		},
		mapped_image,
		"PsSetCreateThreadNotifyRoutine"
	);

	redirect_function(
		[emulator]
		{
			const emulator_t::address_type driver_object = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const std::uint32_t extension_size = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const emulator_t::address_type device_name_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const std::uint32_t device_type = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const emulator_t::address_type rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			std::uint32_t device_characteristics = 0;
			std::uint8_t exclusive = 0;
			emulator_t::address_type device_object_out = 0;

			emulator_err_t error = emulator->read_virtual_memory(rsp + 0x28, &device_characteristics, sizeof(device_characteristics));
			error.throw_if("IoCreateDevice: read DeviceCharacteristics");

			error = emulator->read_virtual_memory(rsp + 0x30, &exclusive, sizeof(exclusive));
			error.throw_if("IoCreateDevice: read Exclusive");

			error = emulator->read_virtual_memory(rsp + 0x38, &device_object_out, sizeof(device_object_out));
			error.throw_if("IoCreateDevice: read DeviceObject");

			std::string name;

			if (device_name_address)
			{
				UNICODE_STRING unicode_string = { };
				error = emulator->read_virtual_memory(device_name_address, &unicode_string, sizeof(unicode_string));
				error.throw_if("IoCreateDevice: read DeviceName");

				const emulator_t::address_type buffer_address = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

				if (buffer_address && unicode_string.Length)
				{
					name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
				}
			}

			const std::uint32_t aligned_extension = (extension_size + 7) & ~7u;
			const std::uint32_t total_size = sizeof(_DEVICE_OBJECT) + aligned_extension;

			const auto allocation = emulator->heap_allocate(total_size, prot_read_write, true);
			error = allocation.error_or({});
			error.throw_if("IoCreateDevice: allocate device object");

			const emulator_t::address_type device_address = *allocation;

			_DEVICE_OBJECT device = { };

			device.Type = 3;
			device.Size = static_cast<USHORT>(extension_size + 336);
			device.ReferenceCount = 1;
			device.DriverObject = reinterpret_cast<_DRIVER_OBJECT*>(driver_object);
			device.DeviceType = device_type;
			device.Characteristics = device_characteristics;
			device.StackSize = 1;
			device.Flags = 0x80;

			if (exclusive)
			{
				device.Flags |= 0x8;
			}

			if (extension_size)
			{
				device.DeviceExtension = reinterpret_cast<PVOID>(device_address + sizeof(_DEVICE_OBJECT));
			}

			error = emulator->write_virtual_memory(device_address, &device, sizeof(device));
			error.throw_if("IoCreateDevice: write device object");

			error = emulator->write_virtual_memory(device_object_out, &device_address, sizeof(device_address));
			error.throw_if("IoCreateDevice: write output pointer");

			spdlog::info("IoCreateDevice called (driver=0x{:X}, ext_size=0x{:X}, name='{}', type=0x{:X}, chars=0x{:X}) -> 0x{:X}",
				driver_object, extension_size, name, device_type, device_characteristics, device_address);

			write_nt_success(emulator);
		},
		mapped_image,
		"IoCreateDevice"
	);

	redirect_function(
		[emulator]
		{
			const emulator_t::address_type device_object = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			std::uint32_t flags = 0;
			emulator_err_t error = emulator->read_virtual_memory(
				device_object + offsetof(_DEVICE_OBJECT, Flags), &flags, sizeof(flags));
			error.throw_if("IoRegisterShutdownNotification: read Flags");

			flags |= 0x800;

			error = emulator->write_virtual_memory(
				device_object + offsetof(_DEVICE_OBJECT, Flags), &flags, sizeof(flags));
			error.throw_if("IoRegisterShutdownNotification: write Flags");

			spdlog::info("IoRegisterShutdownNotification called (device=0x{:X})", device_object);

			write_nt_success(emulator);
		},
		mapped_image,
		"IoRegisterShutdownNotification"
	);

	// todo: actually create symbolic link in object namespace
	redirect_function(
		[emulator]
		{
			const emulator_t::address_type link_name_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const emulator_t::address_type device_name_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			std::string link_name;
			std::string device_name;

			if (link_name_address)
			{
				UNICODE_STRING unicode_string = { };
				static_cast<void>(emulator->read_virtual_memory(link_name_address, &unicode_string, sizeof(unicode_string)));

				const emulator_t::address_type buffer = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

				if (buffer && unicode_string.Length)
				{
					link_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer));
				}
			}

			if (device_name_address)
			{
				UNICODE_STRING unicode_string = { };
				static_cast<void>(emulator->read_virtual_memory(device_name_address, &unicode_string, sizeof(unicode_string)));

				const emulator_t::address_type buffer = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

				if (buffer && unicode_string.Length)
				{
					device_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer));
				}
			}

			spdlog::info("IoCreateSymbolicLink called (link='{}', device='{}')", link_name, device_name);

			write_nt_success(emulator);
		},
		mapped_image,
		"IoCreateSymbolicLink"
	);
}
