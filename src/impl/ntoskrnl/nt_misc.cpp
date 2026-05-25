#include "nt_helpers.hpp"
#include "../../kernel/thread.hpp"
#include "../../util/util.hpp"
#include "../../kernel/exception.hpp"

#include <numeric>
#include <thread>
#include <atomic>
#include <chrono>

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

			THREAD_LOG("KeRegisterBugCheckReasonCallback called (record=0x{:X}, routine=0x{:X}, reason=0x{:X}, component='{}')",
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

			THREAD_LOG("KeDeregisterBugCheckReasonCallback called (record=0x{:X})", record);

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

			THREAD_LOG("KeAreAllApcsDisabled called (irql={}, result={})", irql, result);

			write_return_value(emulator, result);
		},
		mapped_image,
		"KeAreAllApcsDisabled"
	);

	redirect_function(
		[emulator]
		{
			const auto irql = get_guest_irql(emulator);

			THREAD_LOG("KeGetCurrentIrql called (irql={})", irql);

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

			THREAD_LOG("KeInitializeEvent called (event=0x{:X}, type={}, state={})",
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

			THREAD_LOG("KeInitializeTimer called (timer=0x{:X})", timer_address);

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

			THREAD_LOG("KeSetTimer called (timer=0x{:X}, due_time={}, dpc=0x{:X})",
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

	redirect_function(
		[emulator]
		{
			const auto timer_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			std::int32_t signal_state = 0;
			static_cast<void>(emulator->read_virtual_memory(
				timer_address + offsetof(_KEVENT, Header.SignalState), &signal_state, sizeof(signal_state)));

			THREAD_LOG("KeReadStateTimer called (timer=0x{:X}, signal_state={})", timer_address, signal_state);

			write_return_value(emulator, signal_state != 0 ? 1 : 0);
		},
		mapped_image,
		"KeReadStateTimer"
	);

	redirect_function(
		[emulator]
		{
			const auto mutant_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			std::int32_t signal_state = 0;
			static_cast<void>(emulator->read_virtual_memory(
				mutant_address + offsetof(_KEVENT, Header.SignalState), &signal_state, sizeof(signal_state)));

			THREAD_LOG("KeReadStateMutant called (mutant=0x{:X}, signal_state={})", mutant_address, signal_state);

			write_return_value(emulator, static_cast<std::uint64_t>(signal_state));
		},
		mapped_image,
		"KeReadStateMutant"
	);

	redirect_function(
		[emulator]
		{
			const auto process = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto apc_state = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("KeStackAttachProcess called (process=0x{:X}, apc_state=0x{:X})", process, apc_state);
		},
		mapped_image,
		"KeStackAttachProcess"
	);

	redirect_function(
		[emulator]
		{
			const auto apc_state = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("KeUnstackDetachProcess called (apc_state=0x{:X})", apc_state);
		},
		mapped_image,
		"KeUnstackDetachProcess"
	);

	redirect_function(
		[emulator]
		{
			THREAD_LOG("KeEnterCriticalRegion called");
		},
		mapped_image,
		"KeEnterCriticalRegion"
	);

	redirect_function(
		[emulator]
		{
			THREAD_LOG("KeLeaveCriticalRegion called");
		},
		mapped_image,
		"KeLeaveCriticalRegion"
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

			THREAD_LOG("ExCreateCallback called (out=0x{:X}, name='{}', create={}, allow_multiple={})",
				callback_object_out, object_name, create, allow_multiple);

			if (!create && object_name.empty())
			{
				THREAD_WARN_LOG("ExCreateCallback: no name and Create=FALSE, returning STATUS_UNSUCCESSFUL");
				write_nt_status(emulator, 0xC0000001);
				return;
			}

			constexpr std::size_t callback_object_size = 0x38;
			std::array<std::uint8_t, callback_object_size> body{};

			constexpr std::uint32_t signature = 0x6C6C6143;
			std::memcpy(body.data(), &signature, sizeof(signature));

			auto host_object = std::make_shared<callback_object_t>();
			const auto object_address = kernel::object_manager->create_object(0, body.data(), body.size(), host_object);

			const auto list_head_address = object_address + 0x10;
			const std::uint64_t list_pointers[2] = { list_head_address, list_head_address };
			emulator_err_t error = emulator->write_virtual_memory(list_head_address, &list_pointers, sizeof(list_pointers));
			error.throw_if("ExCreateCallback: write RegisteredCallbacks list head");

			error = emulator->write_virtual_memory(object_address + 0x20, &allow_multiple, sizeof(allow_multiple));
			error.throw_if("ExCreateCallback: write AllowMultipleCallbacks");

			error = emulator->write_virtual_memory(callback_object_out, &object_address, sizeof(object_address));
			error.throw_if("ExCreateCallback: write output pointer");

			THREAD_LOG("ExCreateCallback: allocated callback object at 0x{:X}", object_address);

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

			THREAD_LOG("ExRegisterCallback called (object=0x{:X}, function=0x{:X}, context=0x{:X})",
				callback_object, callback_function, callback_context);

			auto host_object = std::make_shared<callback_registration_object_t>();

			constexpr std::size_t registration_body_size = 8;
			std::array<std::uint8_t, registration_body_size> body{};
			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size(), host_object);

			write_return_value(emulator, body_address);
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

			THREAD_LOG("KeSetEvent called (event=0x{:X}, increment={}, wait={}, previous_state={})",
				event_address, increment, wait, previous_state);

			write_return_value(emulator, static_cast<std::uint32_t>(previous_state));
		},
		mapped_image,
		"KeSetEvent"
	);

	const auto clear_event_handler = [emulator](const std::string_view caller_name)
	{
		const auto event_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

		std::int32_t previous_state = 0;

		emulator_err_t error = emulator->read_virtual_memory(
			event_address + offsetof(_KEVENT, Header.SignalState), &previous_state, sizeof(previous_state));
		error.throw_if(std::format("{}: read SignalState", caller_name));

		constexpr std::int32_t not_signaled = 0;

		error = emulator->write_virtual_memory(
			event_address + offsetof(_KEVENT, Header.SignalState), &not_signaled, sizeof(not_signaled));
		error.throw_if(std::format("{}: write SignalState", caller_name));

		THREAD_LOG("{} called (event=0x{:X}, previous_state={})",
			caller_name, event_address, previous_state);

		write_return_value(emulator, static_cast<std::uint32_t>(previous_state));
	};

	redirect_function(
		[clear_event_handler] { clear_event_handler("KeClearEvent"); },
		mapped_image,
		"KeClearEvent"
	);

	redirect_function(
		[clear_event_handler] { clear_event_handler("KeResetEvent"); },
		mapped_image,
		"KeResetEvent"
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

			THREAD_LOG("DbgPrompt called (prompt='{}', response=0x{:X}, length={})",
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

			THREAD_LOG("KeIpiGenericCall called (broadcast_function=0x{:X}, context=0x{:X})",
				broadcast_function, context);

			const auto saved_rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			constexpr std::size_t shadow_space = 0x20 + 8;
			const auto call_stack = emulator->heap_allocate(shadow_space, prot_read_write, true);
			emulator_err_t error = call_stack.error_or({});
			error.throw_if("allocate KeIpiGenericCall stack");

			emulator->write_register<x86::reg::rcx>(context);
			emulator->write_register<x86::reg::rsp>(*call_stack + shadow_space);

			THREAD_LOG("KeIpiGenericCall: invoking guest BroadcastFunction at 0x{:X} with context=0x{:X}",
				broadcast_function, context);

			// use a timeout thread to prevent infinite loops in guest broadcast functions
			// shared_ptr so the flag outlives the lambda if the timeout thread is still sleeping
			auto completed = std::make_shared<std::atomic<bool>>(false);
			std::thread timeout_thread([emulator, completed]
			{
				std::this_thread::sleep_for(std::chrono::seconds(2));
				if (!completed->load())
				{
					static_cast<void>(emulator->stop());
				}
			});
			timeout_thread.detach();

			const auto run_result = emulator->run_at(broadcast_function, emulator_t::thread_return_address);
			completed->store(true);

			if (!run_result)
			{
				THREAD_WARN_LOG("KeIpiGenericCall: guest callback did not complete (timeout or error)");
			}

			emulator->write_register<x86::reg::rsp>(saved_rsp);

			const auto result = run_result ? emulator->read_register<x86::reg::rax, std::uint64_t>() : 0ULL;

			THREAD_LOG("KeIpiGenericCall: guest callback returned 0x{:X}", result);

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

			THREAD_LOG("PsRemoveLoadImageNotifyRoutine called (routine=0x{:X})", routine);

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

			THREAD_LOG("PsRemoveCreateThreadNotifyRoutine called (routine=0x{:X})", routine);

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

			THREAD_LOG("PsSetCreateProcessNotifyRoutine called (routine=0x{:X}, remove={})", routine, remove);

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

			THREAD_LOG("PsSetCreateProcessNotifyRoutineEx called (routine=0x{:X}, remove={})", routine, remove);

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

			THREAD_LOG("KeAcquireSpinLockRaiseToDpc called (spin_lock=0x{:X}, old_irql={})", spin_lock, old_irql);

			write_return_value(emulator, old_irql);
		},
		mapped_image,
		"KeAcquireSpinLockRaiseToDpc"
	);

	redirect_function(
		[emulator]
		{
			const auto spin_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			const auto old_irql = get_guest_irql(emulator);

			constexpr std::uint64_t dispatch_level = 2;
			emulator->write_register<x86::reg::cr8>(dispatch_level);

			THREAD_LOG("ExAcquireSpinLockShared called (spin_lock=0x{:X}, old_irql={})", spin_lock, old_irql);

			write_return_value(emulator, old_irql);
		},
		mapped_image,
		"ExAcquireSpinLockShared"
	);

	redirect_function(
		[emulator]
		{
			const auto spin_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			const auto old_irql = get_guest_irql(emulator);

			constexpr std::uint64_t dispatch_level = 2;
			emulator->write_register<x86::reg::cr8>(dispatch_level);

			THREAD_LOG("ExAcquireSpinLockExclusive called (spin_lock=0x{:X}, old_irql={})", spin_lock, old_irql);

			write_return_value(emulator, old_irql);
		},
		mapped_image,
		"ExAcquireSpinLockExclusive"
	);

	redirect_function(
		[emulator]
		{
			const auto spin_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto old_irql = emulator->read_register<x86::reg::rdx, std::uint8_t>();

			THREAD_LOG("ExReleaseSpinLockShared called (spin_lock=0x{:X}, old_irql={})", spin_lock, old_irql);

			emulator->write_register<x86::reg::cr8>(static_cast<std::uint64_t>(old_irql));
		},
		mapped_image,
		"ExReleaseSpinLockShared"
	);

	redirect_function(
		[emulator]
		{
			const auto spin_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto old_irql = emulator->read_register<x86::reg::rdx, std::uint8_t>();

			THREAD_LOG("ExReleaseSpinLockExclusive called (spin_lock=0x{:X}, old_irql={})", spin_lock, old_irql);

			emulator->write_register<x86::reg::cr8>(static_cast<std::uint64_t>(old_irql));
		},
		mapped_image,
		"ExReleaseSpinLockExclusive"
	);

	redirect_function(
		[emulator]
		{
			const auto spin_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("ExAcquireSpinLockExclusiveAtDpcLevel called (spin_lock=0x{:X})", spin_lock);
		},
		mapped_image,
		"ExAcquireSpinLockExclusiveAtDpcLevel"
	);

	redirect_function(
		[emulator]
		{
			const auto spin_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("ExReleaseSpinLockExclusiveFromDpcLevel called (spin_lock=0x{:X})", spin_lock);
		},
		mapped_image,
		"ExReleaseSpinLockExclusiveFromDpcLevel"
	);

	redirect_function(
		[emulator]
		{
			const auto spin_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto new_irql = emulator->read_register<x86::reg::rdx, std::uint8_t>();

			THREAD_LOG("KeReleaseSpinLock called (spin_lock=0x{:X}, new_irql={})", spin_lock, new_irql);

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

			THREAD_LOG("ExWaitForRundownProtectionRelease called (run_ref=0x{:X})", run_ref);

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

			const auto sleep_ms = std::chrono::milliseconds(std::abs(interval) / 10000);

			THREAD_LOG("KeDelayExecutionThread called (wait_mode={}, alertable={}, interval={}, sleep_ms={})",
				wait_mode, alertable, interval, sleep_ms.count());

			kernel::current_thread->sleep_for(sleep_ms);

			write_nt_success(emulator);

			kernel::switch_thread(emulator, false, true);
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

			THREAD_LOG("KeCancelTimer called (timer=0x{:X}, was_set={})", timer_address, was_set);

			write_return_value(emulator, was_set);
		},
		mapped_image,
		"KeCancelTimer"
	);

	redirect_function(
		[emulator]
		{
			const auto adapter = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("HalPutDmaAdapter called (adapter=0x{:X})", adapter);

			kernel::object_manager->dereference_object(adapter);
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
				THREAD_ERR_LOG("__C_specific_handler: module not found for control_pc 0x{:X}", control_pc);
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

			THREAD_LOG("__C_specific_handler: control_pc_rva=0x{:X}, flags=0x{:X}, scope_count={}, scope_index={}",
				control_pc_rva, record.ExceptionFlags, scope_count, scope_index);

			if ((record.ExceptionFlags & 0x66) != 0)
			{
				// todo: unwind case
				THREAD_LOG("__C_specific_handler: unwind case (flags=0x{:X}), returning continue_search",
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

				THREAD_LOG("__C_specific_handler: scope[{}] begin=0x{:X} end=0x{:X} handler=0x{:X} target=0x{:X}",
					i, scope.begin_address, scope.end_address, scope.handler_address, scope.jump_target);

				if (scope.handler_address == 1)
				{
					const auto target = image_base + scope.jump_target;

					THREAD_LOG("__C_specific_handler: EXCEPTION_EXECUTE_HANDLER, target=0x{:X}", target);

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

				THREAD_LOG("__C_specific_handler: calling filter at 0x{:X}", filter_address);

				const auto run_result = emulator->run_at(filter_address, emulator_t::thread_return_address);
				static_cast<void>(run_result);

				const auto filter_result = emulator->read_register<x86::reg::rax, std::int32_t>();

				emulator->write_register<x86::reg::rcx>(saved_rcx);
				emulator->write_register<x86::reg::rdx>(saved_rdx);
				emulator->write_register<x86::reg::rsp>(saved_rsp);
				emulator->write_register<x86::reg::rip>(saved_rip);

				THREAD_LOG("__C_specific_handler: filter returned {}", filter_result);

				if (filter_result < 0)
				{
					write_return_value(emulator, 0);
					return;
				}

				if (filter_result > 0)
				{
					const auto target = image_base + scope.jump_target;

					THREAD_LOG("__C_specific_handler: jumping to __except at 0x{:X}", target);

					emulator->write_register<x86::reg::rip>(target);
					emulator->write_register<x86::reg::rsp>(establisher_frame);
					skip_return = true;

					return;
				}
			}

			THREAD_LOG("__C_specific_handler: no matching scope, returning continue_search");
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

			THREAD_LOG("PsGetCurrentProcess called (id=0x{:X})", process->id());

			write_return_value(emulator, process_address);
		},
		mapped_image,
		"PsGetCurrentProcess"
	);

	redirect_function(
		[emulator]
		{
			const auto process_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			emulator_t::address_type unique_process_id = 0;
			emulator_err_t error = emulator->read_virtual_memory(
				process_address + offsetof(_EPROCESS, UniqueProcessId), &unique_process_id, sizeof(unique_process_id));
			error.throw_if("PsGetProcessId: read UniqueProcessId");

			THREAD_LOG("PsGetProcessId called (process=0x{:X}, id=0x{:X})", process_address, unique_process_id);

			write_return_value(emulator, unique_process_id);
		},
		mapped_image,
		"PsGetProcessId"
	);

	redirect_function(
		[emulator]
		{
			const auto process = kernel::current_thread->process();
			const auto process_id = process ? process->id() : 0;

			THREAD_LOG("PsGetCurrentThreadProcessId called -> 0x{:X}", process_id);

			write_return_value(emulator, process_id);
		},
		mapped_image,
		"PsGetCurrentThreadProcessId"
	);

	redirect_function(
		kernel::function_implementation_t([emulator](bool& skip_return)
		{
			const auto slist_head = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			if ((slist_head & 0xF) != 0)
			{
				THREAD_WARN_LOG("InitializeSListHead: unaligned address 0x{:X}, raising STATUS_DATATYPE_MISALIGNMENT", slist_head);

				constexpr std::uint32_t status_datatype_misalignment = 0x80000002;
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				kernel::handle_exception(emulator, rip, status_datatype_misalignment, slist_head);
				skip_return = true;

				return;
			}

			constexpr std::array<std::uint64_t, 2> zero = { 0, 0 };

			emulator_err_t error = emulator->write_virtual_memory(slist_head, zero.data(), sizeof(zero));
			error.throw_if("InitializeSListHead: zero header");

			THREAD_LOG("InitializeSListHead called (header=0x{:X})", slist_head);
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

			THREAD_LOG("ExInitializePushLock called (lock=0x{:X})", push_lock);
		},
		mapped_image,
		"ExInitializePushLock"
	);

	// todo: actually track load image notify callbacks
	redirect_function(
		[emulator]
		{
			const auto routine = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("PsSetLoadImageNotifyRoutine called (routine=0x{:X})", routine);

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

			THREAD_LOG("PsLookupProcessByProcessId called (pid={}, out=0x{:X})", process_id, process_out);

			for (const auto& process : kernel::process_entries)
			{
				if (process->id() == process_id)
				{
					const auto address = process->address();

					emulator_err_t error = emulator->write_virtual_memory(process_out, &address, sizeof(address));
					error.throw_if("PsLookupProcessByProcessId: write process");

					THREAD_LOG("PsLookupProcessByProcessId: found process at 0x{:X}", address);

					write_nt_success(emulator);
					return;
				}
			}

			THREAD_WARN_LOG("PsLookupProcessByProcessId: pid {} not found", process_id);

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

			THREAD_LOG("PsGetProcessImageFileName called (process=0x{:X}) -> 0x{:X}",
				process_address, image_file_name_address);

			write_return_value(emulator, image_file_name_address);
		},
		mapped_image,
		"PsGetProcessImageFileName"
	);

	redirect_function(
		[emulator]
		{
			const auto process_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("PsGetProcessWow64Process called (process=0x{:X}) -> 0x0", process_address);

			// all emulated processes are native 64-bit
			write_return_value(emulator, static_cast<emulator_t::address_type>(0));
		},
		mapped_image,
		"PsGetProcessWow64Process"
	);

	const auto read_process_protection = [emulator]() -> _PS_PROTECTION
	{
		const auto process_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

		_PS_PROTECTION protection;
		emulator_err_t error = emulator->read_virtual_memory(
			process_address + offsetof(_EPROCESS, Protection), &protection, sizeof(protection));
		error.throw_if("read _EPROCESS.Protection");

		return protection;
	};

	redirect_function(
		[emulator, read_process_protection]
		{
			const auto protection = read_process_protection();
			const std::uint64_t result = protection.Type != 0;

			THREAD_LOG("PsIsProtectedProcess called (type={}, signer={}, result={})",
				static_cast<std::uint32_t>(protection.Type),
				static_cast<std::uint32_t>(protection.Signer), result);

			write_return_value(emulator, result);
		},
		mapped_image,
		"PsIsProtectedProcess"
	);

	redirect_function(
		[emulator, read_process_protection]
		{
			const auto protection = read_process_protection();
			const std::uint64_t result = protection.Type == 1;

			THREAD_LOG("PsIsProtectedProcessLight called (type={}, signer={}, result={})",
				static_cast<std::uint32_t>(protection.Type),
				static_cast<std::uint32_t>(protection.Signer), result);

			write_return_value(emulator, result);
		},
		mapped_image,
		"PsIsProtectedProcessLight"
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

			THREAD_LOG("KeInitializeGuardedMutex called (mutex=0x{:X})", mutex_address);
		},
		mapped_image,
		"KeInitializeGuardedMutex"
	);

	redirect_function(
		[emulator]
		{
			const auto mutex_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto level = emulator->read_register<x86::reg::rdx, std::uint32_t>();

			std::uint8_t zero[0x38] = {};
			emulator_err_t error = emulator->write_virtual_memory(mutex_address, &zero, sizeof(zero));
			error.throw_if("KeInitializeMutex: zero struct");

			constexpr std::uint8_t mutant_type = 2;
			error = emulator->write_virtual_memory(mutex_address + 0x00, &mutant_type, sizeof(mutant_type));
			error.throw_if("KeInitializeMutex: write Type");

			constexpr std::int32_t signal_state = 1;
			error = emulator->write_virtual_memory(mutex_address + 0x04, &signal_state, sizeof(signal_state));
			error.throw_if("KeInitializeMutex: write SignalState");

			const auto wait_list_head = mutex_address + 0x08;
			const std::uint64_t wait_list_pointers[2] = { wait_list_head, wait_list_head };
			error = emulator->write_virtual_memory(mutex_address + 0x08, &wait_list_pointers, sizeof(wait_list_pointers));
			error.throw_if("KeInitializeMutex: write WaitListHead");

			constexpr std::uint8_t apc_disable = 1;
			error = emulator->write_virtual_memory(mutex_address + 0x31, &apc_disable, sizeof(apc_disable));
			error.throw_if("KeInitializeMutex: write ApcDisable");

			THREAD_LOG("KeInitializeMutex called (mutex=0x{:X}, level={})", mutex_address, level);
		},
		mapped_image,
		"KeInitializeMutex"
	);

	redirect_function(
		[emulator]
		{
			const auto mutex_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto wait = emulator->read_register<x86::reg::rdx, std::uint8_t>();

			// read previous SignalState
			std::int32_t previous_state = 0;
			emulator_err_t error = emulator->read_virtual_memory(mutex_address + 0x04, &previous_state, sizeof(previous_state));
			error.throw_if("KeReleaseMutex: read SignalState");

			// increment SignalState
			const std::int32_t new_state = previous_state + 1;
			error = emulator->write_virtual_memory(mutex_address + 0x04, &new_state, sizeof(new_state));
			error.throw_if("KeReleaseMutex: write SignalState");

			// clear OwnerThread
			constexpr std::uint64_t null_owner = 0;
			error = emulator->write_virtual_memory(mutex_address + 0x28, &null_owner, sizeof(null_owner));
			error.throw_if("KeReleaseMutex: write OwnerThread");

			THREAD_LOG("KeReleaseMutex called (mutex=0x{:X}, wait={}) -> {}", mutex_address, wait, previous_state);

			write_return_value(emulator, static_cast<std::uint64_t>(previous_state));
		},
		mapped_image,
		"KeReleaseMutex"
	);

	redirect_function(
		[emulator]
		{
			const auto mutex_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			// Count = 0 (acquired)
			constexpr std::int32_t count = 0;
			emulator_err_t error = emulator->write_virtual_memory(
				mutex_address + offsetof(_FAST_MUTEX, Count), &count, sizeof(count));
			error.throw_if("ExAcquireFastMutex: write Count");

			// Owner = current thread
			const auto thread_address = kernel::current_thread->address();
			error = emulator->write_virtual_memory(
				mutex_address + offsetof(_FAST_MUTEX, Owner), &thread_address, sizeof(thread_address));
			error.throw_if("ExAcquireFastMutex: write Owner");

			THREAD_LOG("ExAcquireFastMutex called (mutex=0x{:X})", mutex_address);
		},
		mapped_image,
		"ExAcquireFastMutex"
	);

	redirect_function(
		[emulator]
		{
			const auto mutex_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			// Count = 1 (released)
			constexpr std::int32_t count = 1;
			emulator_err_t error = emulator->write_virtual_memory(
				mutex_address + offsetof(_FAST_MUTEX, Count), &count, sizeof(count));
			error.throw_if("ExReleaseFastMutex: write Count");

			// Owner = NULL
			constexpr std::uint64_t null_owner = 0;
			error = emulator->write_virtual_memory(
				mutex_address + offsetof(_FAST_MUTEX, Owner), &null_owner, sizeof(null_owner));
			error.throw_if("ExReleaseFastMutex: write Owner");

			THREAD_LOG("ExReleaseFastMutex called (mutex=0x{:X})", mutex_address);
		},
		mapped_image,
		"ExReleaseFastMutex"
	);

	redirect_function(
		[emulator]
		{
			const auto mutex_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			// Count = 0 (acquired)
			constexpr std::int32_t count = 0;
			emulator_err_t error = emulator->write_virtual_memory(
				mutex_address + offsetof(_FAST_MUTEX, Count), &count, sizeof(count));
			error.throw_if("ExAcquireFastMutexUnsafe: write Count");

			// Owner = current thread
			const auto thread_address = kernel::current_thread->address();
			error = emulator->write_virtual_memory(
				mutex_address + offsetof(_FAST_MUTEX, Owner), &thread_address, sizeof(thread_address));
			error.throw_if("ExAcquireFastMutexUnsafe: write Owner");

			THREAD_LOG("ExAcquireFastMutexUnsafe called (mutex=0x{:X})", mutex_address);
		},
		mapped_image,
		"ExAcquireFastMutexUnsafe"
	);

	redirect_function(
		[emulator]
		{
			const auto mutex_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			// Count = 1 (released)
			constexpr std::int32_t count = 1;
			emulator_err_t error = emulator->write_virtual_memory(
				mutex_address + offsetof(_FAST_MUTEX, Count), &count, sizeof(count));
			error.throw_if("ExReleaseFastMutexUnsafe: write Count");

			// Owner = NULL
			constexpr std::uint64_t null_owner = 0;
			error = emulator->write_virtual_memory(
				mutex_address + offsetof(_FAST_MUTEX, Owner), &null_owner, sizeof(null_owner));
			error.throw_if("ExReleaseFastMutexUnsafe: write Owner");

			THREAD_LOG("ExReleaseFastMutexUnsafe called (mutex=0x{:X})", mutex_address);
		},
		mapped_image,
		"ExReleaseFastMutexUnsafe"
	);

	redirect_function(
		[emulator]
		{
			const auto resource = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("ExInitializeResourceLite called (resource=0x{:X})", resource);

			// zero the ERESOURCE structure (0x68 bytes)
			std::array<std::uint8_t, 0x68> zeroed{};
			static_cast<void>(emulator->write_virtual_memory(resource, zeroed.data(), zeroed.size()));

			write_nt_success(emulator);
		},
		mapped_image,
		"ExInitializeResourceLite"
	);

	redirect_function(
		[emulator]
		{
			const auto resource = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto wait = emulator->read_register<x86::reg::rdx, std::uint8_t>();

			THREAD_LOG("ExAcquireResourceExclusiveLite called (resource=0x{:X}, wait={})", resource, wait);

			write_return_value(emulator, static_cast<std::uint64_t>(1));
		},
		mapped_image,
		"ExAcquireResourceExclusiveLite"
	);

	redirect_function(
		[emulator]
		{
			const auto resource = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto wait = emulator->read_register<x86::reg::rdx, std::uint8_t>();

			THREAD_LOG("ExAcquireResourceSharedLite called (resource=0x{:X}, wait={})", resource, wait);

			write_return_value(emulator, static_cast<std::uint64_t>(1));
		},
		mapped_image,
		"ExAcquireResourceSharedLite"
	);

	redirect_function(
		[emulator]
		{
			const auto resource = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("ExReleaseResourceLite called (resource=0x{:X})", resource);
		},
		mapped_image,
		"ExReleaseResourceLite"
	);

	redirect_function(
		[emulator]
		{
			const auto resource = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("ExDeleteResourceLite called (resource=0x{:X})", resource);

			write_nt_success(emulator);
		},
		mapped_image,
		"ExDeleteResourceLite"
	);

	redirect_function(
		[emulator]
		{
			const auto push_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto flags = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("ExAcquirePushLockExclusiveEx called (push_lock=0x{:X}, flags=0x{:X})", push_lock, flags);
		},
		mapped_image,
		"ExAcquirePushLockExclusiveEx"
	);

	redirect_function(
		[emulator]
		{
			const auto push_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto flags = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("ExReleasePushLockExclusiveEx called (push_lock=0x{:X}, flags=0x{:X})", push_lock, flags);
		},
		mapped_image,
		"ExReleasePushLockExclusiveEx"
	);

	redirect_function(
		[emulator]
		{
			const auto push_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto flags = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("ExAcquirePushLockSharedEx called (push_lock=0x{:X}, flags=0x{:X})", push_lock, flags);
		},
		mapped_image,
		"ExAcquirePushLockSharedEx"
	);

	redirect_function(
		[emulator]
		{
			const auto push_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto flags = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("ExReleasePushLockSharedEx called (push_lock=0x{:X}, flags=0x{:X})", push_lock, flags);
		},
		mapped_image,
		"ExReleasePushLockSharedEx"
	);

	redirect_function(
		[emulator]
		{
			const auto push_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto flags = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("ExReleasePushLockEx called (push_lock=0x{:X}, flags=0x{:X})", push_lock, flags);
		},
		mapped_image,
		"ExReleasePushLockEx"
	);

	redirect_function(
		[emulator]
		{
			const emulator_t::address_type thread_handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const std::uint32_t desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const emulator_t::address_type object_attributes = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const emulator_t::address_type process_handle = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			const emulator_t::address_type rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type client_id_out = 0;
			emulator_t::address_type start_routine = 0;
			emulator_t::address_type start_context = 0;

			emulator_err_t error = emulator->read_virtual_memory(rsp + 0x28, &client_id_out, sizeof(client_id_out));
			error.throw_if("PsCreateSystemThread: read ClientId");

			error = emulator->read_virtual_memory(rsp + 0x30, &start_routine, sizeof(start_routine));
			error.throw_if("PsCreateSystemThread: read StartRoutine");

			error = emulator->read_virtual_memory(rsp + 0x38, &start_context, sizeof(start_context));
			error.throw_if("PsCreateSystemThread: read StartContext");

			const thread_t::id_type thread_id = kernel::object_manager->allocate_id();

			const auto& process = kernel::current_thread->process();
			auto thread = kernel::create_thread(emulator, thread_id, process);

			constexpr emulator_t::size_type thread_stack_size = 0x10000;
			const auto stack_allocation = emulator->heap_allocate(thread_stack_size, prot_read_write, true);
			error = stack_allocation.error_or({});
			error.throw_if("PsCreateSystemThread: allocate thread stack");

			const emulator_t::address_type stack_top = *stack_allocation + thread_stack_size - 0x1000;

			const emulator_t::address_type sentinel = emulator_t::thread_return_address;

			const emulator_t::address_type thread_rsp = (stack_top & ~0xFull) - 8;

			error = emulator->write_virtual_memory(thread_rsp, &sentinel, sizeof(sentinel));
			error.throw_if("PsCreateSystemThread: write sentinel return address");

			thread->state().rip = start_routine;
			thread->state().rcx = start_context;
			thread->state().rsp = thread_rsp;
			thread->state().rflags = 0x202;

			kernel::pending_threads.push(thread);

			if (thread_handle_out)
			{
				kernel::object_manager->register_object(thread->address(), std::make_shared<thread_object_t>(thread));

				const auto handle_value = kernel::object_manager->create_handle(thread->address(), object_manager_t::generic_all);
				error = emulator->write_virtual_memory(thread_handle_out, &handle_value, sizeof(handle_value));
				error.throw_if("PsCreateSystemThread: write handle");
			}

			if (client_id_out)
			{
				const std::uint64_t cid[2] = { process->id(), thread_id };
				error = emulator->write_virtual_memory(client_id_out, &cid, sizeof(cid));
				error.throw_if("PsCreateSystemThread: write ClientId");
			}

			THREAD_LOG("PsCreateSystemThread called (handle_out=0x{:X}, start_routine=0x{:X}, start_context=0x{:X}, tid={}, stack=0x{:X})",
				thread_handle_out, start_routine, start_context, thread_id, stack_top);

			write_nt_success(emulator);
		},
		mapped_image,
		"PsCreateSystemThread"
	);

	redirect_function(
		[emulator](bool& skip_return)
		{
			const auto exit_status = emulator->read_register<x86::reg::rcx, std::uint32_t>();

			THREAD_LOG("PsTerminateSystemThread called (exit_status=0x{:X})", exit_status);

			kernel::switch_thread(emulator, true);

			skip_return = true;
			emulator->write_register<x86::reg::rip>(emulator_t::thread_return_address);
		},
		mapped_image,
		"PsTerminateSystemThread"
	);

	redirect_function(
		[emulator]
		{
			const emulator_t::address_type seed_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			const std::uint32_t result = util::generate_random<std::uint32_t>(0, std::numeric_limits<LONG>::max() - 1);

			emulator_err_t error = emulator->write_virtual_memory(seed_address, &result, sizeof(result));
			error.throw_if("RtlRandomEx: write seed");

			THREAD_LOG("RtlRandomEx called (seed=0x{:X}) -> 0x{:X}", seed_address, result);

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

			THREAD_LOG("PsSetCreateThreadNotifyRoutine called (routine=0x{:X})", routine);

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
			const std::uint32_t total_body_size = sizeof(_DEVICE_OBJECT) + aligned_extension;

			std::vector<std::uint8_t> body(total_body_size, 0);

			auto host_object = std::make_shared<device_object_t>();
			const auto device_address = kernel::object_manager->create_object(0, body.data(), body.size(), host_object);

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

			error = emulator->write_virtual_memory(driver_object + 8, &device_address, sizeof(device_address));
			error.throw_if("IoCreateDevice: write output pointer");

			THREAD_LOG("IoCreateDevice called (driver=0x{:X}, ext_size=0x{:X}, name='{}', type=0x{:X}, chars=0x{:X}) -> 0x{:X}",
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

			THREAD_LOG("IoRegisterShutdownNotification called (device=0x{:X})", device_object);

			write_nt_success(emulator);
		},
		mapped_image,
		"IoRegisterShutdownNotification"
	);

	redirect_function(
		[emulator]
		{
			const auto event_category = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto event_category_flags = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto event_category_data = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto driver_object = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type callback_routine = 0;
			emulator_err_t error = emulator->read_virtual_memory(rsp + 0x28, &callback_routine, sizeof(callback_routine));
			error.throw_if("IoRegisterPlugPlayNotification: read CallbackRoutine");

			emulator_t::address_type context = 0;
			error = emulator->read_virtual_memory(rsp + 0x30, &context, sizeof(context));
			error.throw_if("IoRegisterPlugPlayNotification: read Context");

			emulator_t::address_type notification_entry_ptr = 0;
			error = emulator->read_virtual_memory(rsp + 0x38, &notification_entry_ptr, sizeof(notification_entry_ptr));
			error.throw_if("IoRegisterPlugPlayNotification: read NotificationEntry ptr");

			THREAD_LOG("IoRegisterPlugPlayNotification called (category={}, flags=0x{:X}, data=0x{:X}, driver=0x{:X}, callback=0x{:X}, context=0x{:X}, entry_out=0x{:X})",
				event_category, event_category_flags, event_category_data, driver_object, callback_routine, context, notification_entry_ptr);

			if (notification_entry_ptr)
			{
				const auto dummy_entry = emulator->heap_allocate(0x10, prot_read_write, true);
				error = dummy_entry.error_or({});
				error.throw_if("IoRegisterPlugPlayNotification: allocate entry");

				error = emulator->write_virtual_memory(notification_entry_ptr, &*dummy_entry, sizeof(*dummy_entry));
				error.throw_if("IoRegisterPlugPlayNotification: write NotificationEntry");
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"IoRegisterPlugPlayNotification"
	);

	// IoGetDeviceInterfaces - return empty list (no matching interfaces)
	redirect_function(
		[emulator]
		{
			const auto interface_class_guid = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto physical_device_object = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto flags = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto symbolic_link_list_out = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			THREAD_LOG("IoGetDeviceInterfaces called (guid=0x{:X}, pdo=0x{:X}, flags=0x{:X}, out=0x{:X})",
				interface_class_guid, physical_device_object, flags, symbolic_link_list_out);

			// allocate a double-null terminated empty wide string list
			const auto alloc = emulator->heap_allocate(sizeof(wchar_t) * 2, prot_read_write, true);
			emulator_err_t error = alloc.error_or({});
			error.throw_if("IoGetDeviceInterfaces: allocate empty list");

			constexpr wchar_t empty_list[2] = { L'\0', L'\0' };
			error = emulator->write_virtual_memory(*alloc, &empty_list, sizeof(empty_list));
			error.throw_if("IoGetDeviceInterfaces: write empty list");

			if (symbolic_link_list_out)
			{
				error = emulator->write_virtual_memory(symbolic_link_list_out, &*alloc, sizeof(*alloc));
				error.throw_if("IoGetDeviceInterfaces: write output pointer");
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"IoGetDeviceInterfaces"
	);

	redirect_function(
		[emulator]
		{
			const auto notification_entry = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("IoUnregisterPlugPlayNotificationEx called (entry=0x{:X})", notification_entry);

			write_nt_success(emulator);
		},
		mapped_image,
		"IoUnregisterPlugPlayNotificationEx"
	);

	redirect_function(
		[emulator]
		{
			const auto info_class = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto buffer = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto buffer_size = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto return_size = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			THREAD_LOG("NtManageHotPatch called (info_class={}, buffer=0x{:X}, size={}, return_size_ptr=0x{:X})",
				info_class, buffer, buffer_size, return_size);

			constexpr std::uint32_t status_not_supported = 0xC00000BB;
			write_nt_status(emulator, status_not_supported);
		},
		mapped_image,
		"NtManageHotPatch"
	);

	redirect_function(
		[emulator]
		{
			const auto variable_name = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto vendor_guid = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto value = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto value_length = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			THREAD_LOG("NtQuerySystemEnvironmentValueEx called (name=0x{:X}, guid=0x{:X}, value=0x{:X}, length_ptr=0x{:X})",
				variable_name, vendor_guid, value, value_length);

			constexpr std::uint32_t status_not_implemented = 0xC0000002;
			write_nt_status(emulator, status_not_implemented);
		},
		mapped_image,
		"NtQuerySystemEnvironmentValueEx"
	);

	redirect_function(
		[emulator]
		{
			const auto value_name_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto type_ptr = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto data = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto data_size = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type return_length_ptr = 0;
			emulator_err_t error = emulator->read_virtual_memory(rsp + 0x28, &return_length_ptr, sizeof(return_length_ptr));
			error.throw_if("NtQueryLicenseValue: read ReturnLength ptr");

			std::string name_str;

			if (value_name_address)
			{
				auto us_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, value_name_address);
				const auto us = us_object.read();

				const auto buffer_address = reinterpret_cast<emulator_t::address_type>(us.Buffer);

				if (buffer_address && us.Length > 0)
				{
					const auto wide_name = kernel::read_guest_wstring(*emulator, buffer_address);
					name_str = util::narrow_wstring(wide_name);
				}
			}

			THREAD_LOG("NtQueryLicenseValue called (name='{}', type_ptr=0x{:X}, data=0x{:X}, data_size={}, return_length=0x{:X})",
				name_str, type_ptr, data, data_size, return_length_ptr);

			if (return_length_ptr)
			{
				std::uint32_t zero = 0;
				static_cast<void>(emulator->write_virtual_memory(return_length_ptr, &zero, sizeof(zero)));
			}

			constexpr std::uint32_t status_object_name_not_found = 0xC0000034;
			write_nt_status(emulator, status_object_name_not_found);
		},
		mapped_image,
		"NtQueryLicenseValue"
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

			THREAD_LOG("IoCreateSymbolicLink called (link='{}', device='{}')", link_name, device_name);

			write_nt_success(emulator);
		},
		mapped_image,
		"IoCreateSymbolicLink"
	);

	// todo: actually create symbolic link in object namespace
	redirect_function(
		[emulator]
		{
			const emulator_t::address_type variable_name_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			std::string variable_name;
	
			if (variable_name_address)
			{
				UNICODE_STRING unicode_string = { };
				static_cast<void>(emulator->read_virtual_memory(variable_name_address, &unicode_string, sizeof(unicode_string)));

				const emulator_t::address_type buffer = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

				if (buffer && unicode_string.Length)
				{
					variable_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer));
				}
			}

			THREAD_LOG("ExGetFirmwareEnvironmentVariable called (variable='{}')", variable_name);

			write_nt_success(emulator);
		},
		mapped_image,
		"ExGetFirmwareEnvironmentVariable"
	);

	redirect_function(
		[emulator]
		{
			const auto base = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto num_elements = emulator->read_register<x86::reg::rdx, std::uint64_t>();
			const auto element_size = emulator->read_register<x86::reg::r8, std::uint64_t>();
			const auto comparator = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			THREAD_LOG("qsort called (base=0x{:X}, num={}, size={}, comparator=0x{:X})",
				base, num_elements, element_size, comparator);

			if (!base || num_elements < 2 || !element_size || !comparator)
			{
				return;
			}

			const auto total_size = num_elements * element_size;

			std::vector<std::uint8_t> buffer(total_size);
			emulator_err_t error = emulator->read_virtual_memory(base, buffer.data(), total_size);
			error.throw_if("qsort: read array");

			const auto guest_base = emulator->heap_allocate(total_size, prot_read_write, true);
			error = guest_base.error_or({});
			error.throw_if("qsort: allocate temp buffer");

			error = emulator->write_virtual_memory(*guest_base, buffer.data(), total_size);
			error.throw_if("qsort: write temp buffer");

			const auto saved_rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			constexpr std::size_t shadow_space = 0x20 + 8;
			const auto call_stack = emulator->heap_allocate(shadow_space, prot_read_write, true);
			error = call_stack.error_or({});
			error.throw_if("qsort: allocate call stack");

			std::vector<std::size_t> indices(num_elements);
			std::iota(indices.begin(), indices.end(), 0);

			std::sort(indices.begin(), indices.end(),
				[&](const std::size_t a, const std::size_t b)
				{
					const auto addr_a = *guest_base + a * element_size;
					const auto addr_b = *guest_base + b * element_size;

					emulator->write_register<x86::reg::rcx>(addr_a);
					emulator->write_register<x86::reg::rdx>(addr_b);
					emulator->write_register<x86::reg::rsp>(*call_stack + shadow_space);

					const auto run_result = emulator->run_at(comparator, emulator_t::thread_return_address);

					if (!run_result)
					{
						THREAD_ERR_LOG("qsort: comparator call failed");
						return false;
					}

					const auto result = emulator->read_register<x86::reg::rax, std::int32_t>();

					return result < 0;
				}
			);

			emulator->write_register<x86::reg::rsp>(saved_rsp);

			std::vector<std::uint8_t> sorted(total_size);

			for (std::size_t i = 0; i < num_elements; ++i)
			{
				std::memcpy(sorted.data() + i * element_size,
					buffer.data() + indices[i] * element_size,
					element_size);
			}

			error = emulator->write_virtual_memory(base, sorted.data(), total_size);
			error.throw_if("qsort: write sorted array");

			THREAD_LOG("qsort: sorted {} elements", num_elements);
		},
		mapped_image,
		"qsort"
	);

	const auto wait_for_single_handler = [emulator](const std::string_view caller_name, bool& skip_return)
	{
		const auto object_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
		const auto wait_reason = emulator->read_register<x86::reg::rdx, std::uint32_t>();
		const auto wait_mode = emulator->read_register<x86::reg::r8, std::uint8_t>();
		const auto alertable = emulator->read_register<x86::reg::r9, std::uint8_t>();

		const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
		emulator_t::address_type timeout_ptr = 0;
		static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &timeout_ptr, sizeof(timeout_ptr)));

		std::int64_t timeout_value = 0;
		bool has_timeout = false;

		if (timeout_ptr)
		{
			static_cast<void>(emulator->read_virtual_memory(timeout_ptr, &timeout_value, sizeof(timeout_value)));
			has_timeout = true;
		}

		std::int32_t signal_state = 0;
		static_cast<void>(emulator->read_virtual_memory(
			object_address + offsetof(_KEVENT, Header.SignalState), &signal_state, sizeof(signal_state)));

		THREAD_LOG("{} called (object=0x{:X}, reason={}, mode={}, alertable={}, timeout={}, signal_state={})",
			caller_name, object_address, wait_reason, wait_mode, alertable,
			has_timeout ? std::format("{}", timeout_value) : "infinite", signal_state);

		if (signal_state > 0)
		{
			std::uint8_t object_type = 0;
			static_cast<void>(emulator->read_virtual_memory(
				object_address + offsetof(_KEVENT, Header.Type), &object_type, sizeof(object_type)));

			constexpr std::uint8_t synchronization_event = 1;
			constexpr std::uint8_t semaphore_object = 5;

			if (object_type == synchronization_event)
			{
				const std::int32_t unsignaled = 0;
				static_cast<void>(emulator->write_virtual_memory(
					object_address + offsetof(_KEVENT, Header.SignalState), &unsignaled, sizeof(unsignaled)));
				THREAD_LOG("{} - synchronization event auto-reset (object=0x{:X})", caller_name, object_address);
			}
			else if (object_type == semaphore_object)
			{
				const std::int32_t new_state = signal_state - 1;
				static_cast<void>(emulator->write_virtual_memory(
					object_address + offsetof(_KEVENT, Header.SignalState), &new_state, sizeof(new_state)));
				THREAD_LOG("{} - semaphore decremented (object=0x{:X}, new_state={})", caller_name, object_address, new_state);
			}

			write_nt_status(emulator, 0);
			return;
		}

		if (has_timeout && timeout_value == 0)
		{
			constexpr std::uint32_t status_timeout = 0x102;
			write_nt_status(emulator, status_timeout);
			return;
		}

		constexpr std::uint32_t status_timeout = 0x102;
		constexpr std::int64_t check_interval_100ns = 1000000; // 100ms in 100ns units

		if (has_timeout)
		{
			const auto remaining_100ns = std::abs(timeout_value);

			if (remaining_100ns <= check_interval_100ns)
			{
				const auto sleep_ms = std::chrono::milliseconds(std::max<std::int64_t>(1, remaining_100ns / 10000));
				THREAD_LOG("{} - object not signaled, final sleep {}ms then timeout", caller_name, sleep_ms.count());
				kernel::current_thread->sleep_for(sleep_ms);
				write_nt_status(emulator, status_timeout);
				kernel::switch_thread(emulator, false, true);
			}
			else
			{
				THREAD_LOG("{} - object not signaled, sleeping 100ms and re-checking ({}ms remaining)",
					caller_name, remaining_100ns / 10000);
				kernel::current_thread->sleep_for(std::chrono::milliseconds(100));

				const std::int64_t new_timeout = -(remaining_100ns - check_interval_100ns);
				static_cast<void>(emulator->write_virtual_memory(timeout_ptr, &new_timeout, sizeof(new_timeout)));

				skip_return = true;
				kernel::switch_thread(emulator, false, true);
			}
		}
		else
		{
			THREAD_LOG("{} - object not signaled, sleeping and re-checking (infinite wait)", caller_name);
			kernel::current_thread->sleep_for(std::chrono::milliseconds(100));
			skip_return = true;
			kernel::switch_thread(emulator, false, true);
		}
	};

	redirect_function(
		[wait_for_single_handler](bool& skip_return) { wait_for_single_handler("KeWaitForSingleObject", skip_return); },
		mapped_image,
		"KeWaitForSingleObject"
	);

	redirect_function(
		[emulator, wait_for_single_handler](bool& skip_return)
		{
			const auto count = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto objects_ptr = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto wait_type = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto wait_reason = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			std::uint8_t wait_mode = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &wait_mode, sizeof(wait_mode)));

			std::uint8_t alertable = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &alertable, sizeof(alertable)));

			emulator_t::address_type timeout_ptr = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &timeout_ptr, sizeof(timeout_ptr)));

			std::int64_t timeout_value = 0;
			bool has_timeout = false;

			if (timeout_ptr)
			{
				static_cast<void>(emulator->read_virtual_memory(timeout_ptr, &timeout_value, sizeof(timeout_value)));
				has_timeout = true;
			}

			THREAD_LOG("KeWaitForMultipleObjects called (count={}, objects=0x{:X}, type={}, reason={}, mode={}, alertable={}, timeout={})",
				count, objects_ptr, wait_type, wait_reason, wait_mode, alertable,
				has_timeout ? std::format("{}", timeout_value) : "infinite");

			if (count == 1)
			{
				emulator_t::address_type single_object = 0;
				static_cast<void>(emulator->read_virtual_memory(objects_ptr, &single_object, sizeof(single_object)));

				emulator->write_register<x86::reg::rcx>(single_object);
				emulator->write_register<x86::reg::rdx>(static_cast<std::uint64_t>(wait_reason));
				emulator->write_register<x86::reg::r8>(static_cast<std::uint64_t>(wait_mode));
				emulator->write_register<x86::reg::r9>(static_cast<std::uint64_t>(alertable));

				const auto timeout_on_stack_address = rsp + 0x28;
				static_cast<void>(emulator->write_virtual_memory(timeout_on_stack_address, &timeout_ptr, sizeof(timeout_ptr)));

				wait_for_single_handler("KeWaitForMultipleObjects(1)", skip_return);
				return;
			}

			std::vector<emulator_t::address_type> object_addresses(count);
			emulator_err_t error = emulator->read_virtual_memory(
				objects_ptr, object_addresses.data(), count * sizeof(emulator_t::address_type));
			error.throw_if("KeWaitForMultipleObjects: read object array");

			constexpr std::uint32_t wait_all = 1;
			constexpr std::uint32_t status_timeout = 0x102;
			constexpr std::int64_t check_interval_100ns = 1000000;

			if (wait_type == wait_all)
			{
				bool all_signaled = true;

				for (std::uint32_t i = 0; i < count; ++i)
				{
					std::int32_t signal_state = 0;
					static_cast<void>(emulator->read_virtual_memory(
						object_addresses[i] + offsetof(_KEVENT, Header.SignalState), &signal_state, sizeof(signal_state)));

					THREAD_LOG("  object[{}]=0x{:X} signal_state={}", i, object_addresses[i], signal_state);

					if (signal_state <= 0)
					{
						all_signaled = false;
					}
				}

				if (all_signaled)
				{
					constexpr std::uint8_t synchronization_event = 1;
					constexpr std::uint8_t semaphore_object = 5;

					for (std::uint32_t i = 0; i < count; ++i)
					{
						std::uint8_t object_type = 0;
						static_cast<void>(emulator->read_virtual_memory(
							object_addresses[i] + offsetof(_KEVENT, Header.Type), &object_type, sizeof(object_type)));

						if (object_type == synchronization_event)
						{
							const std::int32_t unsignaled = 0;
							static_cast<void>(emulator->write_virtual_memory(
								object_addresses[i] + offsetof(_KEVENT, Header.SignalState), &unsignaled, sizeof(unsignaled)));
						}
						else if (object_type == semaphore_object)
						{
							std::int32_t state = 0;
							static_cast<void>(emulator->read_virtual_memory(
								object_addresses[i] + offsetof(_KEVENT, Header.SignalState), &state, sizeof(state)));
							const std::int32_t new_state = state - 1;
							static_cast<void>(emulator->write_virtual_memory(
								object_addresses[i] + offsetof(_KEVENT, Header.SignalState), &new_state, sizeof(new_state)));
						}
					}

					write_nt_status(emulator, 0);
					return;
				}

				if (has_timeout && timeout_value == 0)
				{
					write_nt_status(emulator, status_timeout);
					return;
				}

				if (has_timeout)
				{
					const auto remaining_100ns = std::abs(timeout_value);

					if (remaining_100ns <= check_interval_100ns)
					{
						const auto sleep_ms = std::chrono::milliseconds(std::max<std::int64_t>(1, remaining_100ns / 10000));
						THREAD_LOG("KeWaitForMultipleObjects(WaitAll) - not all signaled, final sleep {}ms then timeout", sleep_ms.count());
						kernel::current_thread->sleep_for(sleep_ms);
						write_nt_status(emulator, status_timeout);
						kernel::switch_thread(emulator, false, true);
					}
					else
					{
						THREAD_LOG("KeWaitForMultipleObjects(WaitAll) - not all signaled, sleeping 100ms and re-checking ({}ms remaining)",
							remaining_100ns / 10000);
						kernel::current_thread->sleep_for(std::chrono::milliseconds(100));

						const std::int64_t new_timeout = -(remaining_100ns - check_interval_100ns);
						static_cast<void>(emulator->write_virtual_memory(timeout_ptr, &new_timeout, sizeof(new_timeout)));

						skip_return = true;
						kernel::switch_thread(emulator, false, true);
					}
				}
				else
				{
					THREAD_LOG("KeWaitForMultipleObjects(WaitAll) - not all signaled, sleeping and re-checking (infinite wait)");
					kernel::current_thread->sleep_for(std::chrono::milliseconds(100));
					skip_return = true;
					kernel::switch_thread(emulator, false, true);
				}
			}
			else
			{
				for (std::uint32_t i = 0; i < count; ++i)
				{
					std::int32_t signal_state = 0;
					static_cast<void>(emulator->read_virtual_memory(
						object_addresses[i] + offsetof(_KEVENT, Header.SignalState), &signal_state, sizeof(signal_state)));

					THREAD_LOG("  object[{}]=0x{:X} signal_state={}", i, object_addresses[i], signal_state);

					if (signal_state > 0)
					{
						std::uint8_t object_type = 0;
						static_cast<void>(emulator->read_virtual_memory(
							object_addresses[i] + offsetof(_KEVENT, Header.Type), &object_type, sizeof(object_type)));

						constexpr std::uint8_t synchronization_event = 1;
						constexpr std::uint8_t semaphore_object = 5;

						if (object_type == synchronization_event)
						{
							const std::int32_t unsignaled = 0;
							static_cast<void>(emulator->write_virtual_memory(
								object_addresses[i] + offsetof(_KEVENT, Header.SignalState), &unsignaled, sizeof(unsignaled)));
						}
						else if (object_type == semaphore_object)
						{
							const std::int32_t new_state = signal_state - 1;
							static_cast<void>(emulator->write_virtual_memory(
								object_addresses[i] + offsetof(_KEVENT, Header.SignalState), &new_state, sizeof(new_state)));
						}

						write_nt_status(emulator, static_cast<std::uint32_t>(i));
						return;
					}
				}

				if (has_timeout && timeout_value == 0)
				{
					write_nt_status(emulator, status_timeout);
					return;
				}

				if (has_timeout)
				{
					const auto remaining_100ns = std::abs(timeout_value);

					if (remaining_100ns <= check_interval_100ns)
					{
						const auto sleep_ms = std::chrono::milliseconds(std::max<std::int64_t>(1, remaining_100ns / 10000));
						THREAD_LOG("KeWaitForMultipleObjects(WaitAny) - none signaled, final sleep {}ms then timeout", sleep_ms.count());
						kernel::current_thread->sleep_for(sleep_ms);
						write_nt_status(emulator, status_timeout);
						kernel::switch_thread(emulator, false, true);
					}
					else
					{
						THREAD_LOG("KeWaitForMultipleObjects(WaitAny) - none signaled, sleeping 100ms and re-checking ({}ms remaining)",
							remaining_100ns / 10000);
						kernel::current_thread->sleep_for(std::chrono::milliseconds(100));

						const std::int64_t new_timeout = -(remaining_100ns - check_interval_100ns);
						static_cast<void>(emulator->write_virtual_memory(timeout_ptr, &new_timeout, sizeof(new_timeout)));

						skip_return = true;
						kernel::switch_thread(emulator, false, true);
					}
				}
				else
				{
					THREAD_LOG("KeWaitForMultipleObjects(WaitAny) - none signaled, sleeping and re-checking (infinite wait)");
					kernel::current_thread->sleep_for(std::chrono::milliseconds(100));
					skip_return = true;
					kernel::switch_thread(emulator, false, true);
				}
			}
		},
		mapped_image,
		"KeWaitForMultipleObjects"
	);

	const auto nt_build_number_addr = mapped_image.find_symbol("NtBuildNumber");
	const auto cm_csd_version_addr = mapped_image.find_symbol("CmNtCSDVersion");
	const auto init_phase_addr = mapped_image.find_symbol("InitializationPhase");

	redirect_function(
		[emulator, nt_build_number_addr, cm_csd_version_addr, init_phase_addr]
		{
			const auto version_info_addr = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			std::uint32_t info_size = 0;
			emulator->read_virtual_memory(version_info_addr, &info_size, sizeof(info_size))
				.throw_if("RtlGetVersion: read dwOSVersionInfoSize");

			// read NtBuildNumber from ntoskrnl symbol
			std::uint32_t nt_build_number = 0;
			if (nt_build_number_addr)
			{
				emulator->read_virtual_memory(*nt_build_number_addr, &nt_build_number, sizeof(nt_build_number))
					.throw_if("RtlGetVersion: read NtBuildNumber");
			}

			// check if extended structure (OSVERSIONINFOEXW = 284, or extended variant = 292)
			const bool is_extended = ((info_size - sizeof(OSVERSIONINFOEXW)) & 0xFFFFFFF7) == 0;

			if (is_extended)
			{
				OSVERSIONINFOEXW info = { };
				info.dwOSVersionInfoSize = info_size;
				info.dwMajorVersion = 10; // hardcoded in real ntoskrnl
				info.dwMinorVersion = 0;
				info.dwBuildNumber = nt_build_number & 0xFFFF;
				info.dwPlatformId = VER_PLATFORM_WIN32_NT;

				std::uint32_t cm_csd_version = 0;
				if (cm_csd_version_addr)
				{
					emulator->read_virtual_memory(*cm_csd_version_addr, &cm_csd_version, sizeof(cm_csd_version))
						.throw_if("RtlGetVersion: read CmNtCSDVersion");
				}

				info.wServicePackMajor = static_cast<WORD>((cm_csd_version >> 8) & 0xFF);
				info.wServicePackMinor = static_cast<WORD>(cm_csd_version & 0xFF);

				std::uint32_t init_phase = 0;
				if (init_phase_addr)
				{
					emulator->read_virtual_memory(*init_phase_addr, &init_phase, sizeof(init_phase))
						.throw_if("RtlGetVersion: read InitializationPhase");
				}

				if (init_phase != 0)
				{
					constexpr emulator_t::address_type kuser_shared_data = 0xFFFFF78000000000;

					_KUSER_SHARED_DATA shared_data = { };
					emulator->read_virtual_memory(kuser_shared_data, &shared_data, sizeof(shared_data))
						.throw_if("RtlGetVersion: read KUSER_SHARED_DATA");

					if (shared_data.ProductTypeIsValid)
					{
						info.wProductType = static_cast<BYTE>(shared_data.NtProductType);
					}

					info.wSuiteMask = static_cast<WORD>(shared_data.SuiteMask);
				}

				emulator->write_virtual_memory(version_info_addr, &info, sizeof(info))
					.throw_if("RtlGetVersion: write OSVERSIONINFOEXW");

				THREAD_LOG("RtlGetVersion called (OSVERSIONINFOEXW, version={}.{}.{}, sp={}.{}, product_type={}, suite_mask=0x{:X})",
					info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber,
					info.wServicePackMajor, info.wServicePackMinor, info.wProductType, info.wSuiteMask);
			}
			else
			{
				OSVERSIONINFOW info = { };
				info.dwOSVersionInfoSize = info_size;
				info.dwMajorVersion = 10;
				info.dwMinorVersion = 0;
				info.dwBuildNumber = nt_build_number & 0xFFFF;
				info.dwPlatformId = VER_PLATFORM_WIN32_NT;

				emulator->write_virtual_memory(version_info_addr, &info, sizeof(info))
					.throw_if("RtlGetVersion: write OSVERSIONINFOW");

				THREAD_LOG("RtlGetVersion called (OSVERSIONINFOW, version={}.{}.{})",
					info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber);
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"RtlGetVersion"
	);

	redirect_function(
		[emulator]
		{
			const auto context_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			CONTEXT ctx = {};
			ctx.ContextFlags = 0x10000F;

			ctx.Rax = emulator->read_register<x86::reg::rax, std::uint64_t>();
			ctx.Rcx = context_address;
			ctx.Rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();
			ctx.Rbx = emulator->read_register<x86::reg::rbx, std::uint64_t>();
			ctx.Rsp = rsp + 8;
			ctx.Rbp = emulator->read_register<x86::reg::rbp, std::uint64_t>();
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

			std::uint64_t return_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp, &return_address, sizeof(return_address)));
			ctx.Rip = return_address;

			ctx.EFlags = emulator->read_register<x86::reg::rflags, std::uint32_t>();

			ctx.SegCs = 0x10;
			ctx.SegDs = 0x18;
			ctx.SegEs = 0x18;
			ctx.SegSs = 0x18;
			ctx.SegFs = 0x18;
			ctx.SegGs = 0x18;

			ctx.MxCsr = 0x1F80;
			ctx.FltSave.MxCsr = 0x1F80;

			const auto xmm0 = emulator->read_register<x86::reg::xmm0, xmm_state_register_t>();
			const auto xmm1 = emulator->read_register<x86::reg::xmm1, xmm_state_register_t>();
			const auto xmm2 = emulator->read_register<x86::reg::xmm2, xmm_state_register_t>();
			const auto xmm3 = emulator->read_register<x86::reg::xmm3, xmm_state_register_t>();
			const auto xmm4 = emulator->read_register<x86::reg::xmm4, xmm_state_register_t>();
			const auto xmm5 = emulator->read_register<x86::reg::xmm5, xmm_state_register_t>();
			const auto xmm6 = emulator->read_register<x86::reg::xmm6, xmm_state_register_t>();
			const auto xmm7 = emulator->read_register<x86::reg::xmm7, xmm_state_register_t>();
			const auto xmm8 = emulator->read_register<x86::reg::xmm8, xmm_state_register_t>();
			const auto xmm9 = emulator->read_register<x86::reg::xmm9, xmm_state_register_t>();
			const auto xmm10 = emulator->read_register<x86::reg::xmm10, xmm_state_register_t>();
			const auto xmm11 = emulator->read_register<x86::reg::xmm11, xmm_state_register_t>();
			const auto xmm12 = emulator->read_register<x86::reg::xmm12, xmm_state_register_t>();
			const auto xmm13 = emulator->read_register<x86::reg::xmm13, xmm_state_register_t>();
			const auto xmm14 = emulator->read_register<x86::reg::xmm14, xmm_state_register_t>();
			const auto xmm15 = emulator->read_register<x86::reg::xmm15, xmm_state_register_t>();

			std::memcpy(&ctx.FltSave.XmmRegisters[0], &xmm0, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[1], &xmm1, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[2], &xmm2, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[3], &xmm3, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[4], &xmm4, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[5], &xmm5, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[6], &xmm6, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[7], &xmm7, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[8], &xmm8, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[9], &xmm9, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[10], &xmm10, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[11], &xmm11, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[12], &xmm12, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[13], &xmm13, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[14], &xmm14, sizeof(xmm_state_register_t));
			std::memcpy(&ctx.FltSave.XmmRegisters[15], &xmm15, sizeof(xmm_state_register_t));

			static_cast<void>(emulator->write_virtual_memory(context_address, &ctx, sizeof(ctx)));

			THREAD_LOG("RtlCaptureContext called (context=0x{:X}, rip=0x{:X}, rsp=0x{:X})",
				context_address, ctx.Rip, ctx.Rsp);
		},
		mapped_image,
		"RtlCaptureContext"
	);

	redirect_function(
		[emulator]
		{
			const auto pc_value = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto base_of_image_out = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			emulator_t::address_type image_base = 0;

			if (const auto image = kernel::find_module_from_rip(pc_value))
			{
				image_base = image->base_address();
			}

			if (base_of_image_out)
			{
				static_cast<void>(emulator->write_virtual_memory(base_of_image_out, &image_base, sizeof(image_base)));
			}

			THREAD_LOG("RtlPcToFileHeader called (pc=0x{:X}, base_of_image=0x{:X}) -> 0x{:X}",
				pc_value, base_of_image_out, image_base);

			write_return_value(emulator, image_base);
		},
		mapped_image,
		"RtlPcToFileHeader"
	);

	redirect_function(
		[emulator]
		{
			const auto init_flag = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto signature = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto oem_id = emulator->read_register<x86::reg::r8, std::uint64_t>();
			const auto oem_table_id = emulator->read_register<x86::reg::r9, std::uint64_t>();

			std::array<char, 5> sig_str = {};
			std::memcpy(sig_str.data(), &signature, 4);

			THREAD_LOG("HalAcpiGetTableEx called (init={}, signature='{}', oem_id=0x{:X}, oem_table_id=0x{:X}) -> NULL",
				init_flag, sig_str.data(), oem_id, oem_table_id);

			write_return_value(emulator, 0);
		},
		mapped_image,
		"HalAcpiGetTableEx"
	);

	// todo: properly implement
	// WMI
	redirect_function(
		[emulator]
		{
			const auto guid_address = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto data_block_object_address = emulator->read_register<x86::reg::r8, std::uint64_t>();

			struct guid_t
			{
				std::uint32_t data1;
				std::uint16_t data2;
				std::uint16_t data3;
				std::uint8_t data4[8];
			};

			guid_t guid = {};
			(void)emulator->read_virtual_memory(guid_address, &guid, sizeof(guid));

			THREAD_LOG("IoWMIOpenBlock called (guid={{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}, access=0x{:X}, out=0x{:X}) -> STATUS_WMI_GUID_NOT_FOUND",
				guid.data1, guid.data2, guid.data3,
				guid.data4[0], guid.data4[1], guid.data4[2], guid.data4[3],
				guid.data4[4], guid.data4[5], guid.data4[6], guid.data4[7],
				desired_access, data_block_object_address);

			constexpr std::uint32_t status_wmi_guid_not_found = 0xC0000295;
			write_nt_status(emulator, status_wmi_guid_not_found);
		},
		mapped_image,
		"IoWMIOpenBlock"
	);

	// todo: properly implement
	redirect_function(
		[emulator]
		{
			const auto bus_data_type = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto bus_number = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto slot_number = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto buffer_address = emulator->read_register<x86::reg::r9, std::uint64_t>();
			const auto rsp = emulator->read_register<x86::reg::rsp, std::uint64_t>();

			std::uint32_t offset = 0;
			std::uint32_t length = 0;
			(void)emulator->read_virtual_memory(rsp + 0x28, &offset, sizeof(offset));
			(void)emulator->read_virtual_memory(rsp + 0x30, &length, sizeof(length));

			THREAD_LOG("HalGetBusDataByOffset called (type={}, bus={}, slot={}, buffer=0x{:X}, offset={}, length={}) -> 0",
				bus_data_type, bus_number, slot_number, buffer_address, offset, length);

			write_return_value(emulator, 0);
		},
		mapped_image,
		"HalGetBusDataByOffset"
	);

	redirect_function(
		[emulator]
		{
			const auto semaphore_address = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto count = emulator->read_register<x86::reg::rdx, std::int32_t>();
			const auto limit = emulator->read_register<x86::reg::r8, std::int32_t>();

			// Header.Type = 5 (SemaphoreObject) at offset 0x00
			const std::uint8_t type = 5;
			(void)emulator->write_virtual_memory(semaphore_address + 0x00, &type, sizeof(type));

			// Header.Size = 8 at offset 0x02
			const std::uint8_t size = 8;
			(void)emulator->write_virtual_memory(semaphore_address + 0x02, &size, sizeof(size));

			// Header.SignalState = Count at offset 0x04
			(void)emulator->write_virtual_memory(semaphore_address + 0x04, &count, sizeof(count));

			// Header.WaitListHead (Flink at 0x08, Blink at 0x10) - point to self
			const auto wait_list_head = semaphore_address + 0x08;
			(void)emulator->write_virtual_memory(semaphore_address + 0x08, &wait_list_head, sizeof(wait_list_head));
			(void)emulator->write_virtual_memory(semaphore_address + 0x10, &wait_list_head, sizeof(wait_list_head));

			// Limit at offset 0x18
			(void)emulator->write_virtual_memory(semaphore_address + 0x18, &limit, sizeof(limit));

			THREAD_LOG("KeInitializeSemaphore called (semaphore=0x{:X}, count={}, limit={})",
				semaphore_address, count, limit);
		},
		mapped_image,
		"KeInitializeSemaphore"
	);

	redirect_function(
		[emulator]
		{
			const auto semaphore_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto increment = emulator->read_register<x86::reg::rdx, std::int32_t>();
			const auto adjustment = emulator->read_register<x86::reg::r8, std::int32_t>();
			const auto wait = emulator->read_register<x86::reg::r9, std::uint8_t>();

			// read previous signal state from dispatcher header (offset 0x4)
			std::int32_t previous_state = 0;
			static_cast<void>(emulator->read_virtual_memory(semaphore_address + 0x4, &previous_state, sizeof(previous_state)));

			// update signal state
			const std::int32_t new_state = previous_state + adjustment;
			static_cast<void>(emulator->write_virtual_memory(semaphore_address + 0x4, &new_state, sizeof(new_state)));

			THREAD_LOG("KeReleaseSemaphore called (semaphore=0x{:X}, increment={}, adjustment={}, wait={}) -> prev_state={}",
				semaphore_address, increment, adjustment, wait, previous_state);

			write_return_value(emulator, static_cast<std::uint64_t>(static_cast<std::uint32_t>(previous_state)));
		},
		mapped_image,
		"KeReleaseSemaphore"
	);

	const auto query_information_process = [emulator]
	{
		const auto process_handle = emulator->read_register<x86::reg::rcx, object_manager_t::handle_type>();
		const auto info_class = emulator->read_register<x86::reg::rdx, std::uint32_t>();
		const auto buffer_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
		const auto buffer_length = emulator->read_register<x86::reg::r9, std::uint32_t>();

		const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
		emulator_t::address_type return_length_address = 0;
		static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &return_length_address, sizeof(return_length_address)));

		THREAD_LOG("NtQueryInformationProcess called (handle=0x{:X}, class=0x{:X}, buffer=0x{:X}, length=0x{:X}, return_length=0x{:X})",
			process_handle, info_class, buffer_address, buffer_length, return_length_address);

		constexpr std::uint32_t process_break_on_termination = 0x1D;
		constexpr std::uint32_t process_debug_port = 0x07;
		constexpr std::uint32_t process_basic_information = 0x00;
		constexpr std::uint32_t process_image_file_name = 0x1B;

		if (info_class == process_break_on_termination)
		{
			// return 0 - process is not critical
			const std::uint32_t value = 0;
			if (buffer_address && buffer_length >= sizeof(value))
			{
				emulator->write_virtual_memory(buffer_address, &value, sizeof(value))
					.throw_if("NtQueryInformationProcess: write ProcessBreakOnTermination");
			}
			if (return_length_address)
			{
				const std::uint32_t ret_len = sizeof(value);
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &ret_len, sizeof(ret_len)));
			}

			THREAD_LOG("NtQueryInformationProcess: ProcessBreakOnTermination -> 0");
			write_nt_success(emulator);
		}
		else if (info_class == process_debug_port)
		{
			// return 0 - no debugger attached
			const std::uint64_t value = 0;
			if (buffer_address && buffer_length >= sizeof(value))
			{
				emulator->write_virtual_memory(buffer_address, &value, sizeof(value))
					.throw_if("NtQueryInformationProcess: write ProcessDebugPort");
			}
			if (return_length_address)
			{
				const std::uint32_t ret_len = sizeof(value);
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &ret_len, sizeof(ret_len)));
			}

			THREAD_LOG("NtQueryInformationProcess: ProcessDebugPort -> 0");
			write_nt_success(emulator);
		}
		else if (info_class == process_basic_information)
		{
			// PROCESS_BASIC_INFORMATION structure
			struct
			{
				std::int64_t exit_status;
				std::uint64_t peb_base_address;
				std::uint64_t affinity_mask;
				std::int32_t base_priority;
				std::uint32_t padding;
				std::uint64_t unique_process_id;
				std::uint64_t inherited_from_unique_process_id;
			} basic_info = {};

			basic_info.exit_status = 0x103; // STATUS_PENDING
			basic_info.base_priority = 8;

			// try to get the process ID from the handle
			const auto entry = kernel::object_manager->lookup_handle(process_handle);
			if (entry)
			{
				for (const auto& proc : kernel::process_entries)
				{
					if (proc->address() == entry->body_address)
					{
						basic_info.unique_process_id = proc->id();
						break;
					}
				}
			}

			const auto write_size = std::min(static_cast<std::size_t>(buffer_length), sizeof(basic_info));
			if (buffer_address && write_size)
			{
				emulator->write_virtual_memory(buffer_address, &basic_info, write_size)
					.throw_if("NtQueryInformationProcess: write ProcessBasicInformation");
			}
			if (return_length_address)
			{
				const auto ret_len = static_cast<std::uint32_t>(sizeof(basic_info));
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &ret_len, sizeof(ret_len)));
			}

			THREAD_LOG("NtQueryInformationProcess: ProcessBasicInformation (pid={})", basic_info.unique_process_id);
			write_nt_success(emulator);
		}
		else if (info_class == process_image_file_name)
		{
			// try to get image name from the process
			std::string name;
			const auto entry = kernel::object_manager->lookup_handle(process_handle);
			if (entry)
			{
				for (const auto& proc : kernel::process_entries)
				{
					if (proc->address() == entry->body_address)
					{
						name = proc->name();
						break;
					}
				}
			}

			// build a fake path
			const std::wstring path = L"\\Device\\HarddiskVolume3\\Windows\\System32\\" +
				std::wstring(name.begin(), name.end());

			const auto name_bytes = static_cast<std::uint16_t>(path.size() * sizeof(wchar_t));

			// UNICODE_STRING header + string data
			const std::uint32_t required = sizeof(UNICODE_STRING) + name_bytes + sizeof(wchar_t);

			if (return_length_address)
			{
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &required, sizeof(required)));
			}

			if (buffer_length < required)
			{
				THREAD_LOG("NtQueryInformationProcess: ProcessImageFileName buffer too small (need 0x{:X}, have 0x{:X})",
					required, buffer_length);
				constexpr std::uint32_t status_info_length_mismatch = 0xC0000004;
				write_nt_status(emulator, status_info_length_mismatch);
			}
			else if (buffer_address)
			{
				const auto string_data_address = buffer_address + sizeof(UNICODE_STRING);
				UNICODE_STRING us = {};
				us.Length = name_bytes;
				us.MaximumLength = name_bytes + sizeof(wchar_t);
				us.Buffer = reinterpret_cast<PWSTR>(string_data_address);

				emulator->write_virtual_memory(buffer_address, &us, sizeof(us))
					.throw_if("NtQueryInformationProcess: write UNICODE_STRING header");
				emulator->write_virtual_memory(string_data_address, path.data(), name_bytes)
					.throw_if("NtQueryInformationProcess: write image name");

				THREAD_LOG("NtQueryInformationProcess: ProcessImageFileName -> '{}'", name);
				write_nt_success(emulator);
			}
			else
			{
				write_nt_success(emulator);
			}
		}
		else
		{
			THREAD_WARN_LOG("NtQueryInformationProcess: unhandled class 0x{:X}", info_class);
			constexpr std::uint32_t status_invalid_info_class = 0xC0000003;
			write_nt_status(emulator, status_invalid_info_class);
		}
	};

	redirect_function(
		[query_information_process] { query_information_process(); },
		mapped_image,
		"NtQueryInformationProcess"
	);

	redirect_function(
		[query_information_process] { query_information_process(); },
		mapped_image,
		"ZwQueryInformationProcess"
	);

	const auto query_active_processor_count = [emulator]
	{
		const auto group_number = emulator->read_register<x86::reg::rcx, std::uint16_t>();

		constexpr std::uint32_t count = 8;

		THREAD_LOG("KeQueryActiveProcessorCountEx called (group=0x{:X}) -> {}", group_number, count);

		write_return_value(emulator, count);
	};

	redirect_function(
		[query_active_processor_count] { query_active_processor_count(); },
		mapped_image,
		"KeQueryActiveProcessorCountEx"
	);

	redirect_function(
		[query_active_processor_count] { query_active_processor_count(); },
		mapped_image,
		"KeQueryActiveProcessorCount"
	);

	redirect_function(
		[emulator]
		{
			const auto callback_type = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto callback_function = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("SeRegisterImageVerificationCallback called (type=0x{:X}, callback=0x{:X})",
				callback_type, callback_function);

			write_nt_success(emulator);
		},
		mapped_image,
		"SeRegisterImageVerificationCallback"
	);
}
