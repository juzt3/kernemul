#include "nt_helpers.hpp"

namespace kernel
{
	std::shared_ptr<mapped_image_t> find_module(std::string_view name);
}

static std::uint8_t get_guest_irql(const std::shared_ptr<emulator_t>& emulator)
{
	return emulator->read_register<x86::reg::cr8, std::uint8_t>();
}

void redirect_ntoskrnl_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image)
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
				component_name = read_guest_string(*emulator, r9);
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
						object_name = narrow_wstring(read_guest_wstring(*emulator, buffer_address));
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

	redirect_function(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			if (!rcx)
			{
				spdlog::warn("MmGetSystemRoutineAddress called with null argument");
				write_return_value(emulator, 0);
				return;
			}

			const auto us = emulator_object_t<UNICODE_STRING>::view_at(emulator, rcx).read();
			const auto buffer_address = reinterpret_cast<emulator_t::address_type>(us.Buffer);

			std::string routine_name;

			if (buffer_address && us.Length)
			{
				routine_name = narrow_wstring(read_guest_wstring(*emulator, buffer_address));
			}

			spdlog::info("MmGetSystemRoutineAddress called (name='{}')", routine_name);

			if (routine_name.empty())
			{
				write_return_value(emulator, 0);
				return;
			}

			emulator_t::address_type result = 0;

			if (const auto ntoskrnl = kernel::find_module("ntoskrnl.exe"))
			{
				if (const auto address = ntoskrnl->find_symbol(routine_name))
				{
					result = *address;
				}
			}

			if (!result)
			{
				if (const auto hal = kernel::find_module("HAL.dll"))
				{
					if (const auto address = hal->find_symbol(routine_name))
					{
						result = *address;
					}
				}
			}

			if (result)
			{
				spdlog::info("MmGetSystemRoutineAddress: found '{}' at 0x{:X}", routine_name, result);
			}
			else
			{
				spdlog::warn("MmGetSystemRoutineAddress: '{}' not found", routine_name);
			}

			write_return_value(emulator, result);
		},
		mapped_image,
		"MmGetSystemRoutineAddress"
	);

	redirect_function(
		[emulator]
		{
			const auto broadcast_function = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto context = emulator->read_register<x86::reg::rdx, std::uint64_t>();

			spdlog::info("KeIpiGenericCall called (broadcast_function=0x{:X}, context=0x{:X})", broadcast_function, context);

			const auto saved_rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			constexpr std::uint64_t shadow_space_size = 0x20;
			constexpr std::uint64_t return_address_size = 8;

			auto call_rsp = saved_rsp - shadow_space_size - return_address_size;
			call_rsp &= ~0xFull;
			call_rsp -= return_address_size;

			emulator_err_t error = emulator->write_virtual_memory(
				call_rsp, &emulator_t::thread_return_address, sizeof(emulator_t::thread_return_address));

			error.throw_if("KeIpiGenericCall: write return address");

			emulator->write_register<x86::reg::rsp>(call_rsp);
			emulator->write_register<x86::reg::rcx>(context);

			spdlog::info("KeIpiGenericCall: invoking guest BroadcastFunction at 0x{:X} with context=0x{:X}", broadcast_function, context);

			error = emulator->run_at(broadcast_function, emulator_t::thread_return_address);

			error.throw_if("KeIpiGenericCall: run guest callback");

			const auto result = emulator->read_register<x86::reg::rax, std::uint64_t>();

			spdlog::info("KeIpiGenericCall: guest BroadcastFunction returned 0x{:X}", result);

			emulator->write_register<x86::reg::rsp>(saved_rsp);

			write_return_value(emulator, result);
		},
		mapped_image,
		"KeIpiGenericCall"
	);

	// todo: implement exception injection
	redirect_function(
		[emulator]
		{
			const auto prompt_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto response_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto length = emulator->read_register<x86::reg::r8, std::uint32_t>();

			std::string prompt;

			if (prompt_address)
			{
				prompt = read_guest_string(*emulator, prompt_address);
			}

			spdlog::info("DbgPrompt called (prompt='{}', response=0x{:X}, length={})",
				prompt, response_address, length);

			write_return_value(emulator, 0);
		},
		mapped_image,
		"DbgPrompt"
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

	// todo: actually delete the symbolic link from the object namespace
	redirect_function(
		[emulator]
		{
			const auto name_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			std::string link_name;

			if (name_address)
			{
				const auto us = emulator_object_t<UNICODE_STRING>::view_at(emulator, name_address).read();
				const auto buffer_address = reinterpret_cast<emulator_t::address_type>(us.Buffer);

				if (buffer_address && us.Length)
				{
					link_name = narrow_wstring(read_guest_wstring(*emulator, buffer_address));
				}
			}

			spdlog::info("IoDeleteSymbolicLink called (name='{}')", link_name);

			write_nt_success(emulator);
		},
		mapped_image,
		"IoDeleteSymbolicLink"
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
}
