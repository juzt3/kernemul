#include "nt_helpers.hpp"
#include "../../kernel/thread.hpp"
#include "../../kernel/segments.hpp"
#include "../../kernel/exception_common.hpp"
#include "../../util/util.hpp"
#include "../../kernel/exception.hpp"
#include "../../user/user.hpp"
#include "../../user/user_memory.hpp"
#include "../../user/exception_dispatch.hpp"

#include <Windows.h>
#include <numeric>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <vector>

using nt_query_information_process_fn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static nt_query_information_process_fn get_host_nt_query_information_process()
{
	static const auto fn = reinterpret_cast<nt_query_information_process_fn>(
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));

	return fn;
}

static std::uint8_t get_guest_irql(const std::shared_ptr<emulator_t>& emulator)
{
	return emulator->read_register<x86::reg::cr8, std::uint8_t>();
}

void redirect_ntoskrnl_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
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

	redirect_function(
		[emulator]
		{
			const auto timer_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto due_time = emulator->read_register<x86::reg::rdx, std::int64_t>();
			const auto dpc = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			// convert relative due time to absolute
			std::uint64_t absolute_due_time;

			if (due_time < 0)
			{
				FILETIME ft;
				GetSystemTimeAsFileTime(&ft);
				const auto now = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
				absolute_due_time = now + static_cast<std::uint64_t>(-due_time);
			}
			else
			{
				absolute_due_time = static_cast<std::uint64_t>(due_time);
			}

			THREAD_LOG("KeSetTimer called (timer=0x{:X}, due_time={}, absolute=0x{:X}, dpc=0x{:X})",
				timer_address, due_time, absolute_due_time, dpc);

			// unsignal the timer
			constexpr std::int32_t unsignaled = 0;
			emulator_err_t error = emulator->write_virtual_memory(
				timer_address + offsetof(_KTIMER, Header.SignalState), &unsignaled, sizeof(unsignaled));
			error.throw_if("KeSetTimer: unsignal");

			error = emulator->write_virtual_memory(
				timer_address + offsetof(_KTIMER, DueTime), &absolute_due_time, sizeof(absolute_due_time));
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

			constexpr emulator_t::size_type stack_size = 0x4000;
			const auto call_stack = emulator->heap_allocate(stack_size, prot_read_write, true);
			emulator_err_t error = call_stack.error_or({});
			error.throw_if("allocate KeIpiGenericCall stack");

			const emulator_t::address_type rsp = ((*call_stack + stack_size) & ~0xFull) - 0x28;
			const emulator_t::address_type sentinel = emulator_t::thread_return_address;
			error = emulator->write_virtual_memory(rsp, &sentinel, sizeof(sentinel));
			error.throw_if("KeIpiGenericCall: write return sentinel");

			emulator->write_register<x86::reg::rcx>(context);
			emulator->write_register<x86::reg::rsp>(rsp);

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

			if (run_result)
			{
				THREAD_WARN_LOG("KeIpiGenericCall: guest callback did not complete (timeout or error)");
			}

			emulator->write_register<x86::reg::rsp>(saved_rsp);

			const auto result = !run_result ? emulator->read_register<x86::reg::rax, std::uint64_t>() : 0ULL;

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

			const auto* scopes = reinterpret_cast<const exception_common::scope_entry_t*>(&scope_table_ptr[1]);

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

				constexpr emulator_t::size_type filter_stack_size = 0x4000;
				const auto filter_alloc = emulator->heap_allocate(filter_stack_size, prot_read_write, true);
				error = filter_alloc.error_or({});
				error.throw_if("__C_specific_handler: allocate filter stack");

				const auto pointers_address = *filter_alloc;
				const std::uint64_t exception_pointers[2] = { exception_record_addr, context_record_addr };
				error = emulator->write_virtual_memory(pointers_address, &exception_pointers, sizeof(exception_pointers));
				error.throw_if("__C_specific_handler: write exception pointers");

				const emulator_t::address_type filter_rsp = ((*filter_alloc + filter_stack_size) & ~0xFull) - 0x28;
				const emulator_t::address_type filter_sentinel = emulator_t::thread_return_address;
				error = emulator->write_virtual_memory(filter_rsp, &filter_sentinel, sizeof(filter_sentinel));
				error.throw_if("__C_specific_handler: write return sentinel");

				const auto saved_rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();
				const auto saved_rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();
				const auto saved_rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
				const auto saved_rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				emulator->write_register<x86::reg::rcx>(pointers_address);
				emulator->write_register<x86::reg::rdx>(establisher_frame);
				emulator->write_register<x86::reg::rsp>(filter_rsp);

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
			const auto file_object_out = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("PsReferenceProcessFilePointer called (process=0x{:X}, file_object_out=0x{:X})",
				process_address, file_object_out);

			if (file_object_out)
			{
				const auto fake_file_object = emulator->heap_allocate(0x100, prot_read_write, true);
				auto error = fake_file_object.error_or({});
				error.throw_if("PsReferenceProcessFilePointer: allocate fake file object");

				error = emulator->write_virtual_memory(file_object_out, &fake_file_object.value(), sizeof(fake_file_object.value()));
				error.throw_if("PsReferenceProcessFilePointer: write file object pointer");
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"PsReferenceProcessFilePointer"
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

			_EPROCESS eprocess{};
			static_cast<void>(emulator->read_virtual_memory(process_address + offsetof(_EPROCESS, SectionBaseAddress),
				&eprocess.SectionBaseAddress, sizeof(eprocess.SectionBaseAddress)));

			const auto result = reinterpret_cast<emulator_t::address_type>(eprocess.SectionBaseAddress);

			THREAD_LOG("PsGetProcessSectionBaseAddress called (process=0x{:X}) -> 0x{:X}",
				process_address, result);

			write_return_value(emulator, result);
		},
		mapped_image,
		"PsGetProcessSectionBaseAddress"
	);

	redirect_function(
		[emulator]
		{
			const auto process_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("PsGetProcessSessionId called (process=0x{:X}) -> 0", process_address);

			write_return_value(emulator, static_cast<std::uint32_t>(0));
		},
		mapped_image,
		"PsGetProcessSessionId"
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

	redirect_function(
		[emulator]
		{
			const auto process_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			std::uint32_t flags = 0;
			const auto error = emulator->read_virtual_memory(
				process_address + offsetof(_EPROCESS, Flags), &flags, sizeof(flags));
			error.throw_if("PsGetProcessExitProcessCalled: read Flags");

			const auto exit_called = (flags & 4) != 0;

			THREAD_LOG("PsGetProcessExitProcessCalled called (process=0x{:X}, flags=0x{:X}) -> {}",
				process_address, flags, exit_called);

			write_return_value(emulator, static_cast<std::uint64_t>(exit_called ? 1 : 0));
		},
		mapped_image,
		"PsGetProcessExitProcessCalled"
	);

	redirect_function(
		[emulator]
		{
			const auto process_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("PsAcquireProcessExitSynchronization called (process=0x{:X})", process_address);

			write_nt_success(emulator);
		},
		mapped_image,
		"PsAcquireProcessExitSynchronization"
	);

	redirect_function(
		[emulator]
		{
			const auto process_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("PsReleaseProcessExitSynchronization called (process=0x{:X})", process_address);
		},
		mapped_image,
		"PsReleaseProcessExitSynchronization"
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
			const auto thread_handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type client_id_out = 0;
			emulator_t::address_type start_routine = 0;
			emulator_t::address_type start_context = 0;

			emulator_err_t error = emulator->read_virtual_memory(rsp + 0x28, &client_id_out, sizeof(client_id_out));
			error.throw_if("PsCreateSystemThread: read ClientId");

			error = emulator->read_virtual_memory(rsp + 0x30, &start_routine, sizeof(start_routine));
			error.throw_if("PsCreateSystemThread: read StartRoutine");

			error = emulator->read_virtual_memory(rsp + 0x38, &start_context, sizeof(start_context));
			error.throw_if("PsCreateSystemThread: read StartContext");

			const std::uint64_t args[] = { start_context };
			auto thread = kernel::create_thread_at(emulator, start_routine, args);

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
				const auto& process = kernel::current_thread->process();
				const std::uint64_t cid[2] = { process->id(), thread->id() };
				error = emulator->write_virtual_memory(client_id_out, &cid, sizeof(cid));
				error.throw_if("PsCreateSystemThread: write ClientId");
			}

			THREAD_LOG("PsCreateSystemThread called (handle_out=0x{:X}, start_routine=0x{:X}, start_context=0x{:X}, tid={})",
				thread_handle_out, start_routine, start_context, thread->id());

			write_nt_success(emulator);
		},
		mapped_image,
		"PsCreateSystemThread"
	);

	redirect_function(
		[emulator]
		{
			const auto thread_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto increment = emulator->read_register<x86::reg::rdx, std::int32_t>();

			THREAD_LOG("KeSetBasePriorityThread called (thread=0x{:X}, increment={})", thread_address, increment);

			write_return_value(emulator, static_cast<std::uint64_t>(0));
		},
		mapped_image,
		"KeSetBasePriorityThread"
	);

	redirect_function(
		[emulator]
		{
			const auto object_name_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto attributes = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto access_state = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type object_type = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &object_type, sizeof(object_type)));

			std::uint8_t access_mode = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &access_mode, sizeof(access_mode)));

			emulator_t::address_type parse_context = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &parse_context, sizeof(parse_context)));

			emulator_t::address_type object_out = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x40, &object_out, sizeof(object_out)));

			std::wstring name;
			if (object_name_address)
			{
				const auto us = emulator_object_t<UNICODE_STRING>::view_at(emulator, object_name_address).read();
				const auto buf_addr = reinterpret_cast<emulator_t::address_type>(us.Buffer);
				name = kernel::read_guest_wstring(*emulator, buf_addr);
			}

			THREAD_LOG("ObReferenceObjectByName called (name='{}', attrs=0x{:X}, access=0x{:X}, type=0x{:X}, object_out=0x{:X})",
				util::narrow_wstring(name), attributes, desired_access, object_type, object_out);

			const auto narrow_name = util::narrow_wstring(name);
			const auto found = kernel::object_manager->lookup_named_object(narrow_name);

			if (found && object_out)
			{
				const auto obj_addr = *found;
				emulator_err_t error = emulator->write_virtual_memory(object_out, &obj_addr, sizeof(obj_addr));
				error.throw_if("ObReferenceObjectByName: write object pointer");

				THREAD_LOG("ObReferenceObjectByName: found at 0x{:X}", obj_addr);
				write_nt_success(emulator);
			}
			else
			{
				THREAD_WARN_LOG("ObReferenceObjectByName: '{}' not found", narrow_name);
				constexpr std::uint32_t status_object_name_not_found = 0xC0000034;
				write_nt_status(emulator, status_object_name_not_found);
			}
		},
		mapped_image,
		"ObReferenceObjectByName"
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
			const auto device_object = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("IoDeleteDevice called (device=0x{:X})", device_object);
		},
		mapped_image,
		"IoDeleteDevice"
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

	redirect_function(
		[emulator]
		{
			const auto irp_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto priority_boost = emulator->read_register<x86::reg::rdx, std::uint8_t>();

			THREAD_LOG("IofCompleteRequest called (irp=0x{:X}, priority_boost={})", irp_address, priority_boost);
		},
		mapped_image,
		"IofCompleteRequest"
	);

	redirect_function(
		[emulator]
		{
			THREAD_LOG("IoGetTopLevelIrp called -> 0x0");

			write_return_value(emulator, static_cast<std::uint64_t>(0));
		},
		mapped_image,
		"IoGetTopLevelIrp"
	);

	redirect_function(
		[emulator]
		{
			const auto irp = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("IoSetTopLevelIrp called (irp=0x{:X})", irp);
		},
		mapped_image,
		"IoSetTopLevelIrp"
	);

	redirect_function(
		[emulator]
		{
			const auto value_name_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto type_out = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto data = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto data_size = emulator->read_register<x86::reg::r9, std::uint32_t>();

			std::wstring name;
			if (value_name_address)
			{
				const auto us = emulator_object_t<UNICODE_STRING>::view_at(emulator, value_name_address).read();
				const auto buf_addr = reinterpret_cast<emulator_t::address_type>(us.Buffer);
				name = kernel::read_guest_wstring(*emulator, buf_addr);
			}

			THREAD_LOG("ZwQueryLicenseValue called (name='{}', data=0x{:X}, size={})",
				util::narrow_wstring(name), data, data_size);

			constexpr std::uint32_t status_object_name_not_found = 0xC0000034;
			write_nt_status(emulator, status_object_name_not_found);
		},
		mapped_image,
		"ZwQueryLicenseValue"
	);

	redirect_function(
		[emulator]
		{
			const auto work_item_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto queue_type = emulator->read_register<x86::reg::rdx, std::uint32_t>();

			// WORK_QUEUE_ITEM: LIST_ENTRY(16) + WorkerRoutine(8) + Parameter(8)
			emulator_t::address_type worker_routine = 0;
			emulator->read_virtual_memory(work_item_address + 0x10, &worker_routine, sizeof(worker_routine))
				.throw_if("ExQueueWorkItem: read WorkerRoutine");

			emulator_t::address_type parameter = 0;
			emulator->read_virtual_memory(work_item_address + 0x18, &parameter, sizeof(parameter))
				.throw_if("ExQueueWorkItem: read Parameter");

			THREAD_LOG("ExQueueWorkItem called (work_item=0x{:X}, queue_type={}, routine=0x{:X}, param=0x{:X})",
				work_item_address, queue_type, worker_routine, parameter);

			// the parameter is often an event that the caller waits on
			// signal it preemptively in case the work item thread crashes
			if (parameter)
			{
				const std::int32_t signaled = 1;
				static_cast<void>(emulator->write_virtual_memory(
					parameter + offsetof(_KEVENT, Header.SignalState), &signaled, sizeof(signaled)));
			}

			const std::uint64_t args[] = { parameter };
			auto thread = kernel::create_thread_at(emulator, worker_routine, args);
			kernel::pending_threads.push(thread);
		},
		mapped_image,
		"ExQueueWorkItem"
	);

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

			constexpr emulator_t::size_type callback_stack_size = 0x4000;
			const auto call_stack = emulator->heap_allocate(callback_stack_size, prot_read_write, true);
			error = call_stack.error_or({});
			error.throw_if("qsort: allocate call stack");

			const emulator_t::address_type callback_rsp = ((*call_stack + callback_stack_size) & ~0xFull) - 0x28;
			const emulator_t::address_type sentinel = emulator_t::thread_return_address;
			error = emulator->write_virtual_memory(callback_rsp, &sentinel, sizeof(sentinel));
			error.throw_if("qsort: write return sentinel");

			std::vector<std::size_t> indices(num_elements);
			std::iota(indices.begin(), indices.end(), 0);

			std::sort(indices.begin(), indices.end(),
				[&](const std::size_t a, const std::size_t b)
				{
					const auto addr_a = *guest_base + a * element_size;
					const auto addr_b = *guest_base + b * element_size;

					emulator->write_register<x86::reg::rcx>(addr_a);
					emulator->write_register<x86::reg::rdx>(addr_b);
					emulator->write_register<x86::reg::rsp>(callback_rsp);

					const auto run_result = emulator->run_at(comparator, emulator_t::thread_return_address);

					if (run_result)
					{
						const auto failed_rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
						const auto failed_rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
						THREAD_ERR_LOG("qsort: comparator call failed (rip=0x{:X}, rsp=0x{:X})", failed_rip, failed_rsp);
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

		// check if the object is a timer that has expired
		if (signal_state <= 0)
		{
			std::uint8_t obj_type = 0;
			static_cast<void>(emulator->read_virtual_memory(
				object_address + offsetof(_KEVENT, Header.Type), &obj_type, sizeof(obj_type)));

			constexpr std::uint8_t timer_notification = 8;
			constexpr std::uint8_t timer_synchronization = 9;

			if (obj_type == timer_notification || obj_type == timer_synchronization)
			{
				union _ULARGE_INTEGER due_time = {};
				static_cast<void>(emulator->read_virtual_memory(
					object_address + offsetof(_KTIMER, DueTime), &due_time, sizeof(due_time)));

				if (due_time.QuadPart != 0)
				{
					FILETIME ft;
					GetSystemTimeAsFileTime(&ft);
					const auto now = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

					if (now >= due_time.QuadPart)
					{
						signal_state = 1;
						static_cast<void>(emulator->write_virtual_memory(
							object_address + offsetof(_KEVENT, Header.SignalState), &signal_state, sizeof(signal_state)));
						THREAD_LOG("{} - timer expired, signaling (object=0x{:X})", caller_name, object_address);
					}
				}
			}
		}

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

			// helper to check and auto-signal expired timers
			const auto check_timer_expiration = [&emulator](emulator_t::address_type obj_addr, std::int32_t& sig_state)
			{
				if (sig_state > 0)
				{
					return;
				}

				std::uint8_t obj_type = 0;
				static_cast<void>(emulator->read_virtual_memory(
					obj_addr + offsetof(_KEVENT, Header.Type), &obj_type, sizeof(obj_type)));

				constexpr std::uint8_t timer_notification = 8;
				constexpr std::uint8_t timer_synchronization = 9;

				if (obj_type != timer_notification && obj_type != timer_synchronization)
				{
					return;
				}

				union _ULARGE_INTEGER due_time = {};
				static_cast<void>(emulator->read_virtual_memory(
					obj_addr + offsetof(_KTIMER, DueTime), &due_time, sizeof(due_time)));

				if (due_time.QuadPart == 0)
				{
					return;
				}

				FILETIME ft;
				GetSystemTimeAsFileTime(&ft);
				const auto now = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

				if (now >= due_time.QuadPart)
				{
					sig_state = 1;
					static_cast<void>(emulator->write_virtual_memory(
						obj_addr + offsetof(_KEVENT, Header.SignalState), &sig_state, sizeof(sig_state)));
					THREAD_LOG("KeWaitForMultipleObjects - timer expired, signaling (object=0x{:X})", obj_addr);
				}
			};

			if (wait_type == wait_all)
			{
				bool all_signaled = true;

				for (std::uint32_t i = 0; i < count; ++i)
				{
					std::int32_t signal_state = 0;
					static_cast<void>(emulator->read_virtual_memory(
						object_addresses[i] + offsetof(_KEVENT, Header.SignalState), &signal_state, sizeof(signal_state)));

					check_timer_expiration(object_addresses[i], signal_state);

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

					check_timer_expiration(object_addresses[i], signal_state);

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

			exception_common::read_xmms(emulator, ctx);

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

			// handle NtCurrentProcess() pseudo-handle
			constexpr std::uint64_t nt_current_process = 0xFFFFFFFFFFFFFFFF;
			if (process_handle == nt_current_process)
			{
				// use the system process (pid=4)
				if (!kernel::process_entries.empty())
				{
					basic_info.unique_process_id = kernel::process_entries[0]->id();
				}
			}
			else
			{
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
			}

			if (user::usermode_peb_address)
			{
				basic_info.peb_base_address = user::usermode_peb_address;
			}
			else
			{
				static emulator_t::address_type fake_peb_address = 0;
				if (!fake_peb_address)
				{
					const auto peb_alloc = emulator->heap_allocate(0x1000, prot_read_write, true);
					peb_alloc.error_or({}).throw_if("NtQueryInformationProcess: allocate fake PEB");
					fake_peb_address = *peb_alloc;

					const auto params_alloc = emulator->heap_allocate(0x400, prot_read_write, true);
					params_alloc.error_or({}).throw_if("NtQueryInformationProcess: allocate fake ProcessParameters");
					const auto params_addr = *params_alloc;

					emulator->write_virtual_memory(fake_peb_address + 0x20, &params_addr, sizeof(params_addr))
						.throw_if("NtQueryInformationProcess: write PEB->ProcessParameters");
				}
				basic_info.peb_base_address = fake_peb_address;
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
				util::widen_string(name);

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
		else if (info_class == 0x24)
		{
			// ProcessCookie (36 = 0x24) - used by CRT __security_init_cookie
			constexpr std::uint32_t process_cookie = 0x01234567;

			if (buffer_address && buffer_length >= sizeof(process_cookie))
			{
				static_cast<void>(emulator->write_virtual_memory(buffer_address, &process_cookie, sizeof(process_cookie)));
			}
			if (return_length_address)
			{
				const std::uint32_t ret_len = sizeof(process_cookie);
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &ret_len, sizeof(ret_len)));
			}

			THREAD_LOG("NtQueryInformationProcess: ProcessCookie -> 0x{:X}", process_cookie);
			write_nt_success(emulator);
		}
		else if (info_class == 0x25)
		{
			THREAD_LOG("NtQueryInformationProcess: class 0x25 (ProcessMitigationPolicy) -> zeroed buffer");

			if (buffer_address && buffer_length > 0)
			{
				std::vector<std::uint8_t> zeros(buffer_length, 0);
				static_cast<void>(emulator->write_virtual_memory(buffer_address, zeros.data(), buffer_length));
			}

			write_nt_success(emulator);
		}
		else
		{
			constexpr std::uint32_t status_invalid_info_class = 0xC0000003;
			THREAD_LOG("NtQueryInformationProcess: unhandled class 0x{:X}, returning STATUS_INVALID_INFO_CLASS",
				info_class);
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

	const auto query_information_thread = [emulator]
	{
		const auto thread_handle = emulator->read_register<x86::reg::rcx, std::uint64_t>();
		const auto info_class = emulator->read_register<x86::reg::rdx, std::uint32_t>();
		const auto buffer_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
		const auto buffer_length = emulator->read_register<x86::reg::r9, std::uint32_t>();

		const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
		emulator_t::address_type return_length_address = 0;
		static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &return_length_address, sizeof(return_length_address)));

		THREAD_LOG("ZwQueryInformationThread called (handle=0x{:X}, class=0x{:X}, buffer=0x{:X}, length=0x{:X})",
			thread_handle, info_class, buffer_address, buffer_length);

		constexpr std::uint32_t thread_basic_information = 0x00;
		constexpr std::uint32_t thread_is_terminated = 0x14;

		if (info_class == thread_basic_information)
		{
			// THREAD_BASIC_INFORMATION: ExitStatus(4) + pad(4) + TebBaseAddress(8) + ClientId(16) + AffinityMask(8) + Priority(4) + BasePriority(4)
			struct
			{
				std::int32_t exit_status;
				std::uint32_t padding;
				std::uint64_t teb_base_address;
				std::uint64_t unique_process;
				std::uint64_t unique_thread;
				std::uint64_t affinity_mask;
				std::int32_t priority;
				std::int32_t base_priority;
			} info = {};

			info.exit_status = 0x103; // STATUS_PENDING
			info.affinity_mask = 0xFF;
			info.priority = 8;
			info.base_priority = 8;

			const auto write_size = std::min(static_cast<std::size_t>(buffer_length), sizeof(info));
			if (buffer_address && write_size)
			{
				emulator->write_virtual_memory(buffer_address, &info, write_size)
					.throw_if("ZwQueryInformationThread: write ThreadBasicInformation");
			}
			if (return_length_address)
			{
				const auto ret_len = static_cast<std::uint32_t>(sizeof(info));
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &ret_len, sizeof(ret_len)));
			}

			THREAD_LOG("ZwQueryInformationThread: ThreadBasicInformation");
			write_nt_success(emulator);
		}
		else if (info_class == 0x09) // ThreadQuerySetWin32StartAddress
		{
			// read Win32StartAddress from current thread's ETHREAD
			std::uint64_t start_address = 0;

			constexpr std::uint64_t nt_current_thread = 0xFFFFFFFFFFFFFFFE;
			if (thread_handle == nt_current_thread && kernel::current_thread)
			{
				emulator->read_virtual_memory(
					kernel::current_thread->address() + offsetof(_ETHREAD, Win32StartAddress),
					&start_address, sizeof(start_address))
					.throw_if("ZwQueryInformationThread: read Win32StartAddress");
			}

			if (buffer_address && buffer_length >= sizeof(std::uint64_t))
			{
				emulator->write_virtual_memory(buffer_address, &start_address, sizeof(start_address))
					.throw_if("ZwQueryInformationThread: write ThreadQuerySetWin32StartAddress");
			}
			if (return_length_address)
			{
				const std::uint32_t ret_len = sizeof(std::uint64_t);
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &ret_len, sizeof(ret_len)));
			}

			THREAD_LOG("ZwQueryInformationThread: ThreadQuerySetWin32StartAddress -> 0x{:X}", start_address);
			write_nt_success(emulator);
		}
		else if (info_class == thread_is_terminated)
		{
			if (buffer_address && buffer_length >= sizeof(std::uint32_t))
			{
				const std::uint32_t terminated = 0;
				emulator->write_virtual_memory(buffer_address, &terminated, sizeof(terminated))
					.throw_if("ZwQueryInformationThread: write ThreadIsTerminated");
			}

			THREAD_LOG("ZwQueryInformationThread: ThreadIsTerminated -> false");
			write_nt_success(emulator);
		}
		else
		{
			THREAD_WARN_LOG("ZwQueryInformationThread: unhandled class 0x{:X}", info_class);
			constexpr std::uint32_t status_invalid_info_class = 0xC0000003;
			write_nt_status(emulator, status_invalid_info_class);
		}
	};

	redirect_function(query_information_thread, mapped_image, "NtQueryInformationThread");
	redirect_function(query_information_thread, mapped_image, "ZwQueryInformationThread");

	const auto query_active_processor_count = [emulator]
	{
		const auto group_number = emulator->read_register<x86::reg::rcx, std::uint16_t>();

		constexpr std::uint32_t count = kernel::processor_count;

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

	// NtSetInformationThread(ThreadHandle, InfoClass, Buffer, Length)
	const auto set_information_thread = [emulator]
	{
		const auto thread_handle = read_raw_arg(emulator, 0);
		const auto info_class = static_cast<std::uint32_t>(read_raw_arg(emulator, 1));
		const auto buffer_address = read_raw_arg(emulator, 2);
		const auto buffer_length = static_cast<std::uint32_t>(read_raw_arg(emulator, 3));

		THREAD_LOG("NtSetInformationThread called (handle=0x{:X}, class=0x{:X}, buf=0x{:X}, len=0x{:X})",
			thread_handle, info_class, buffer_address, buffer_length);

		constexpr std::uint32_t thread_hide_from_debugger = 0x11;
		constexpr std::uint32_t thread_zero_tls_cell = 0x17;
		constexpr std::uint32_t thread_base_priority = 0x03;
		constexpr std::uint32_t thread_scheduler_shared_data_slot = 0x23;

		if (info_class == thread_hide_from_debugger)
		{
			THREAD_LOG("NtSetInformationThread: ThreadHideFromDebugger (ignored)");
		}
		else if (info_class == thread_zero_tls_cell)
		{
			THREAD_LOG("NtSetInformationThread: ThreadZeroTlsCell (ignored)");
		}
		else if (info_class == thread_base_priority)
		{
			THREAD_LOG("NtSetInformationThread: ThreadBasePriority (ignored)");
		}
		else if (info_class == thread_scheduler_shared_data_slot)
		{
			THREAD_LOG("NtSetInformationThread: ThreadSchedulerSharedDataSlot (ignored)");
		}
		else
		{
			THREAD_WARN_LOG("NtSetInformationThread: unhandled class 0x{:X}", info_class);
		}

		write_nt_success(emulator);
	};

	redirect_function(set_information_thread, mapped_image, "NtSetInformationThread");
	redirect_function(set_information_thread, mapped_image, "ZwSetInformationThread");

	// NtSetInformationProcess(ProcessHandle, InfoClass, Buffer, Length)
	const auto set_information_process = [emulator]
	{
		const auto process_handle = read_raw_arg(emulator, 0);
		const auto info_class = static_cast<std::uint32_t>(read_raw_arg(emulator, 1));
		const auto buffer_address = read_raw_arg(emulator, 2);
		const auto buffer_length = static_cast<std::uint32_t>(read_raw_arg(emulator, 3));

		THREAD_LOG("NtSetInformationProcess called (handle=0x{:X}, class=0x{:X}, buf=0x{:X}, len=0x{:X})",
			process_handle, info_class, buffer_address, buffer_length);

		write_nt_success(emulator);
	};

	redirect_function(set_information_process, mapped_image, "NtSetInformationProcess");
	redirect_function(set_information_process, mapped_image, "ZwSetInformationProcess");

	// NtContinue(ContextRecord*, RaiseAlert)
	redirect_function(
		kernel::function_implementation_t(
			[emulator](bool& skip_return)
			{
				skip_return = true;

				const auto context_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
				const auto raise_alert = emulator->read_register<x86::reg::rdx, std::uint32_t>();

				THREAD_LOG("NtContinue called (context=0x{:X}, raise_alert={})", context_address, raise_alert);

				CONTEXT ctx{};
				static_cast<void>(emulator->read_virtual_memory(context_address, &ctx, sizeof(ctx)));

				emulator->write_register<x86::reg::rax>(ctx.Rax);
				emulator->write_register<x86::reg::rcx>(ctx.Rcx);
				emulator->write_register<x86::reg::rdx>(ctx.Rdx);
				emulator->write_register<x86::reg::rbx>(ctx.Rbx);
				emulator->write_register<x86::reg::rsp>(ctx.Rsp);
				emulator->write_register<x86::reg::rbp>(ctx.Rbp);
				emulator->write_register<x86::reg::rsi>(ctx.Rsi);
				emulator->write_register<x86::reg::rdi>(ctx.Rdi);
				emulator->write_register<x86::reg::r8>(ctx.R8);
				emulator->write_register<x86::reg::r9>(ctx.R9);
				emulator->write_register<x86::reg::r10>(ctx.R10);
				emulator->write_register<x86::reg::r11>(ctx.R11);
				emulator->write_register<x86::reg::r12>(ctx.R12);
				emulator->write_register<x86::reg::r13>(ctx.R13);
				emulator->write_register<x86::reg::r14>(ctx.R14);
				emulator->write_register<x86::reg::r15>(ctx.R15);
				emulator->write_register<x86::reg::rip>(ctx.Rip);

				rflags flags = { .flags = static_cast<std::uint64_t>(ctx.EFlags) };
				flags.read_as_1 = 1;
				emulator->write_register<x86::reg::rflags>(flags.flags);

				const auto cs_sel = static_cast<std::uint16_t>(ctx.SegCs);
				const auto ss_sel = static_cast<std::uint16_t>(ctx.SegSs);

				if (cs_sel == kernel::user_cs_selector)
				{
					kernel::swap_to_usermode_segments(emulator);

					const auto gs_base = kernel::current_thread->state().gs_base;
					kernel::swap_to_usermode_gs(emulator, gs_base);
				}

				THREAD_LOG("NtContinue: restoring to RIP=0x{:X}, RSP=0x{:X}, CS=0x{:X}",
					ctx.Rip, ctx.Rsp, cs_sel);

				user::clear_exception_dispatch_guard();
			}
		),
		mapped_image,
		"NtContinue"
	);

	// NtYieldExecution()
	redirect_function(
		[emulator]
		{
			THREAD_LOG("NtYieldExecution called");
			write_nt_status(emulator, 0x40000024); // STATUS_NO_YIELD_PERFORMED
		},
		mapped_image,
		"NtYieldExecution"
	);

	// NtOpenDirectoryObject(DirectoryHandle*, DesiredAccess, ObjectAttributes*)
	redirect_function(
		[emulator]
		{
			const auto handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto oa_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			std::string dir_name;

			if (oa_address)
			{
				auto oa = emulator_object_t<OBJECT_ATTRIBUTES>::view_at(emulator, oa_address);
				const auto oa_val = oa.read();
				const auto name_addr = reinterpret_cast<emulator_t::address_type>(oa_val.ObjectName);

				if (name_addr)
				{
					auto us = emulator_object_t<UNICODE_STRING>::view_at(emulator, name_addr);
					const auto us_val = us.read();
					const auto buf = reinterpret_cast<emulator_t::address_type>(us_val.Buffer);

					if (buf && us_val.Length > 0)
					{
						dir_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buf));
					}
				}
			}

			THREAD_LOG("NtOpenDirectoryObject called (handle_out=0x{:X}, access=0x{:X}, name='{}')",
				handle_out, desired_access, dir_name);

			constexpr std::size_t dir_body_size = 0x10;
			std::array<std::uint8_t, dir_body_size> body{};

			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size());
			const auto dir_handle = kernel::object_manager->create_handle(body_address, desired_access);

			kernel::object_manager->register_named_object(dir_name, body_address);

			if (handle_out)
			{
				static_cast<void>(emulator->write_virtual_memory(handle_out, &dir_handle, sizeof(dir_handle)));
			}

			THREAD_LOG("NtOpenDirectoryObject: created handle 0x{:X} for '{}'", dir_handle, dir_name);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtOpenDirectoryObject"
	);

	// NtOpenSymbolicLinkObject(LinkHandle*, DesiredAccess, ObjectAttributes*)
	redirect_function(
		[emulator]
		{
			const auto handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto oa_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			std::string link_name;

			if (oa_address)
			{
				auto oa = emulator_object_t<OBJECT_ATTRIBUTES>::view_at(emulator, oa_address);
				const auto oa_val = oa.read();
				const auto name_addr = reinterpret_cast<emulator_t::address_type>(oa_val.ObjectName);

				if (name_addr)
				{
					auto us = emulator_object_t<UNICODE_STRING>::view_at(emulator, name_addr);
					const auto us_val = us.read();
					const auto buf = reinterpret_cast<emulator_t::address_type>(us_val.Buffer);

					if (buf && us_val.Length > 0)
					{
						link_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buf));
					}
				}
			}

			THREAD_LOG("NtOpenSymbolicLinkObject called (handle_out=0x{:X}, access=0x{:X}, name='{}')",
				handle_out, desired_access, link_name);

			constexpr std::size_t body_size = 0x10;
			std::array<std::uint8_t, body_size> body{};

			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size());
			const auto link_handle = kernel::object_manager->create_handle(body_address, desired_access);

			if (handle_out)
			{
				static_cast<void>(emulator->write_virtual_memory(handle_out, &link_handle, sizeof(link_handle)));
			}

			THREAD_LOG("NtOpenSymbolicLinkObject: created handle 0x{:X} for '{}'", link_handle, link_name);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtOpenSymbolicLinkObject"
	);

	// NtQuerySymbolicLinkObject(LinkHandle, LinkTarget*, ReturnedLength*)
	redirect_function(
		[emulator]
		{
			const auto link_handle = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto target_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto return_length_ptr = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			THREAD_LOG("NtQuerySymbolicLinkObject called (handle=0x{:X}, target=0x{:X})",
				link_handle, target_address);

			// return the System32 path for KnownDllPath
			constexpr std::wstring_view system32_path = L"C:\\Windows\\System32";

			if (target_address)
			{
				auto us = emulator_object_t<UNICODE_STRING>::view_at(emulator, target_address);
				auto us_val = us.read();

				const auto buf_addr = reinterpret_cast<emulator_t::address_type>(us_val.Buffer);
				const auto max_len = us_val.MaximumLength;
				const auto needed = static_cast<std::uint16_t>(system32_path.size() * sizeof(wchar_t));

				if (buf_addr && max_len >= needed)
				{
					static_cast<void>(emulator->write_virtual_memory(buf_addr, system32_path.data(), needed));
					us_val.Length = needed;
					us.write(us_val);
				}
			}

			if (return_length_ptr)
			{
				const auto len = static_cast<std::uint32_t>(system32_path.size() * sizeof(wchar_t));
				static_cast<void>(emulator->write_virtual_memory(return_length_ptr, &len, sizeof(len)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtQuerySymbolicLinkObject"
	);

	// NtQueryAttributesFile(ObjectAttributes*, FileBasicInformation*)
	redirect_function(
		[emulator]
		{
			const auto oa_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto info_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			std::string file_path;

			if (oa_address)
			{
				auto oa = emulator_object_t<OBJECT_ATTRIBUTES>::view_at(emulator, oa_address);
				const auto oa_val = oa.read();
				const auto name_addr = reinterpret_cast<emulator_t::address_type>(oa_val.ObjectName);

				if (name_addr)
				{
					auto us = emulator_object_t<UNICODE_STRING>::view_at(emulator, name_addr);
					const auto us_val = us.read();
					const auto buf = reinterpret_cast<emulator_t::address_type>(us_val.Buffer);

					if (buf && us_val.Length > 0)
					{
						file_path = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buf));
					}
				}
			}

			THREAD_LOG("NtQueryAttributesFile called (path='{}')", file_path);

			// normalize and check if file exists in our vfs
			auto normalized = file_path;
			for (auto& c : normalized)
			{
				if (c == '\\') c = '/';
				c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
			}

			auto strip_prefix = [](std::string& s, std::string_view prefix)
			{
				std::string lower(prefix);
				for (auto& c : lower)
				{
					if (c == '\\') c = '/';
					c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
				}
				if (s.starts_with(lower))
				{
					s = s.substr(lower.size());
				}
			};

			strip_prefix(normalized, "\\device\\");
			strip_prefix(normalized, "\\??\\");
			strip_prefix(normalized, "\\dosdevices\\");
			strip_prefix(normalized, "\\systemroot\\");

			if (const auto hdv_pos = normalized.find("harddiskvolume"); hdv_pos == 0)
			{
				if (const auto slash = normalized.find('/', hdv_pos); slash != std::string::npos)
				{
					normalized = normalized.substr(slash + 1);
					if (normalized.starts_with("windows/"))
					{
						normalized = normalized.substr(8);
					}
				}
			}

			if (normalized.size() >= 3
				&& std::isalpha(static_cast<unsigned char>(normalized[0]))
				&& normalized[1] == ':'
				&& normalized[2] == '/')
			{
				normalized = normalized.substr(3);
			}

			if (normalized.starts_with("windows/"))
			{
				normalized = normalized.substr(8);
			}

			const auto file = kernel::filesystem->open_at(normalized);

			if (file)
			{
				// write basic info - all zeros except file exists
				if (info_address)
				{
					struct
					{
						std::int64_t creation_time;
						std::int64_t last_access_time;
						std::int64_t last_write_time;
						std::int64_t change_time;
						std::uint32_t file_attributes;
					} basic_info = {};

					basic_info.file_attributes = 0x20; // FILE_ATTRIBUTE_ARCHIVE
					static_cast<void>(emulator->write_virtual_memory(info_address, &basic_info, sizeof(basic_info)));
				}

				THREAD_LOG("NtQueryAttributesFile: found '{}'", normalized);
				write_nt_success(emulator);
			}
			else
			{
				THREAD_LOG("NtQueryAttributesFile: not found '{}'", normalized);
				write_nt_status(emulator, 0xC0000034); // STATUS_OBJECT_NAME_NOT_FOUND
			}
		},
		mapped_image,
		"NtQueryAttributesFile"
	);

	// NtQueryPerformanceCounter(PerformanceCounter*, PerformanceFrequency*)
	redirect_function(
		[emulator]
		{
			const auto counter_ptr = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto frequency_ptr = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("NtQueryPerformanceCounter called");

			if (counter_ptr)
			{
				LARGE_INTEGER counter;
				QueryPerformanceCounter(&counter);
				static_cast<void>(emulator->write_virtual_memory(counter_ptr, &counter, sizeof(counter)));
			}

			if (frequency_ptr)
			{
				LARGE_INTEGER frequency;
				QueryPerformanceFrequency(&frequency);
				static_cast<void>(emulator->write_virtual_memory(frequency_ptr, &frequency, sizeof(frequency)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtQueryPerformanceCounter"
	);

	// NtQuerySystemTime(SystemTime*)
	redirect_function(
		[emulator]
		{
			const auto time_ptr = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("NtQuerySystemTime called");

			if (time_ptr)
			{
				LARGE_INTEGER time;
				GetSystemTimeAsFileTime(reinterpret_cast<FILETIME*>(&time));
				static_cast<void>(emulator->write_virtual_memory(time_ptr, &time, sizeof(time)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtQuerySystemTime"
	);

	// NtSetThreadExecutionState(NewFlags, PreviousFlags*)
	redirect_function(
		[emulator]
		{
			const auto new_flags = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto prev_ptr = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("NtSetThreadExecutionState called (flags=0x{:X})", new_flags);

			if (prev_ptr)
			{
				const std::uint32_t prev = 0;
				static_cast<void>(emulator->write_virtual_memory(prev_ptr, &prev, sizeof(prev)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtSetThreadExecutionState"
	);

	// NtNotifyChangeKey(KeyHandle, Event, ...)
	redirect_function(
		[emulator]
		{
			THREAD_LOG("NtNotifyChangeKey called (stubbed)");
			write_nt_status(emulator, 0x00000103); // STATUS_PENDING
		},
		mapped_image,
		"NtNotifyChangeKey"
	);

	// NtFlushBuffersFile(FileHandle, IoStatusBlock*)
	redirect_function(
		[emulator]
		{
			const auto file_handle = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			THREAD_LOG("NtFlushBuffersFile called (handle=0x{:X})", file_handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtFlushBuffersFile"
	);

	// NtQueryDefaultLocale(UserProfile, DefaultLocaleId*)
	redirect_function(
		[emulator]
		{
			const auto user_profile = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto locale_id_ptr = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("NtQueryDefaultLocale called (user_profile={})", user_profile);

			if (locale_id_ptr)
			{
				constexpr std::uint32_t en_us = 0x0409;
				static_cast<void>(emulator->write_virtual_memory(locale_id_ptr, &en_us, sizeof(en_us)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtQueryDefaultLocale"
	);

	// NtQueryDefaultUILanguage(DefaultUILanguageId*)
	redirect_function(
		[emulator]
		{
			const auto lang_ptr = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("NtQueryDefaultUILanguage called");

			if (lang_ptr)
			{
				constexpr std::uint16_t en_us = 0x0409;
				static_cast<void>(emulator->write_virtual_memory(lang_ptr, &en_us, sizeof(en_us)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtQueryDefaultUILanguage"
	);

	// NtQueryInstallUILanguage(InstallUILanguageId*)
	redirect_function(
		[emulator]
		{
			const auto lang_ptr = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("NtQueryInstallUILanguage called");

			if (lang_ptr)
			{
				constexpr std::uint16_t en_us = 0x0409;
				static_cast<void>(emulator->write_virtual_memory(lang_ptr, &en_us, sizeof(en_us)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtQueryInstallUILanguage"
	);

	// NtCreateEvent(EventHandle*, DesiredAccess, ObjectAttributes*, EventType, InitialState)
	redirect_function(
		[emulator]
		{
			const auto handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto oa_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto event_type = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
			std::uint32_t initial_state = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &initial_state, sizeof(initial_state)));

			THREAD_LOG("NtCreateEvent called (handle_out=0x{:X}, access=0x{:X}, type={}, initial={})",
				handle_out, desired_access, event_type, initial_state);

			constexpr std::size_t event_body_size = 0x18;
			std::array<std::uint8_t, event_body_size> body{};
			body[0] = static_cast<std::uint8_t>(event_type);
			body[1] = static_cast<std::uint8_t>(initial_state);

			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size());
			const auto event_handle = kernel::object_manager->create_handle(body_address, desired_access);

			if (handle_out)
			{
				static_cast<void>(emulator->write_virtual_memory(handle_out, &event_handle, sizeof(event_handle)));
			}

			THREAD_LOG("NtCreateEvent: created handle 0x{:X}", event_handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtCreateEvent"
	);

	// NtOpenEvent(EventHandle*, DesiredAccess, ObjectAttributes*)
	redirect_function(
		[emulator]
		{
			const auto handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto oa_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			std::string event_name;

			if (oa_address)
			{
				emulator_t::address_type name_address = 0;
				static_cast<void>(emulator->read_virtual_memory(
					oa_address + offsetof(OBJECT_ATTRIBUTES, ObjectName), &name_address, sizeof(name_address)));

				if (name_address)
				{
					const auto us = emulator_object_t<UNICODE_STRING>::view_at(emulator, name_address).read();
					const auto buffer_address = reinterpret_cast<emulator_t::address_type>(us.Buffer);

					if (buffer_address && us.Length)
					{
						event_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
					}
				}
			}

			THREAD_LOG("NtOpenEvent called (handle_out=0x{:X}, access=0x{:X}, name='{}')",
				handle_out, desired_access, event_name);

			constexpr std::size_t event_body_size = 0x18;
			std::array<std::uint8_t, event_body_size> body{};

			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size());
			const auto event_handle = kernel::object_manager->create_handle(body_address, desired_access);

			if (handle_out)
			{
				static_cast<void>(emulator->write_virtual_memory(handle_out, &event_handle, sizeof(event_handle)));
			}

			THREAD_LOG("NtOpenEvent: created handle 0x{:X}", event_handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtOpenEvent"
	);

	// NtDuplicateObject(SourceProcess, SourceHandle, TargetProcess, TargetHandle*, DesiredAccess, HandleAttributes, Options)
	redirect_function(
		[emulator]
		{
			const auto source_process = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto source_handle = emulator->read_register<x86::reg::rdx, std::uint64_t>();
			const auto target_process = emulator->read_register<x86::reg::r8, std::uint64_t>();
			const auto target_handle_out = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			const auto desired_access = static_cast<std::uint32_t>(read_raw_arg(emulator, 4));
			const auto handle_attributes = static_cast<std::uint32_t>(read_raw_arg(emulator, 5));
			const auto options = static_cast<std::uint32_t>(read_raw_arg(emulator, 6));

			constexpr std::uint32_t duplicate_close_source = 0x1;
			constexpr std::uint32_t duplicate_same_access = 0x2;

			THREAD_LOG("NtDuplicateObject called (src_proc=0x{:X}, src_handle=0x{:X}, tgt_proc=0x{:X}, tgt_out=0x{:X}, access=0x{:X}, attr=0x{:X}, opts=0x{:X})",
				source_process, source_handle, target_process, target_handle_out, desired_access, handle_attributes, options);

			if (target_handle_out)
			{
				emulator_t::address_type body_address = 0;
				object_manager_t::access_type access = 0x1F0FFF;

				constexpr auto nt_current_process = static_cast<std::uint64_t>(-1);
				constexpr auto nt_current_thread = static_cast<std::uint64_t>(-2);

				if (source_handle == nt_current_process)
				{
					body_address = kernel::current_thread->process()->address();
					THREAD_LOG("NtDuplicateObject: resolving NtCurrentProcess pseudo-handle -> body 0x{:X}", body_address);
				}
				else if (source_handle == nt_current_thread)
				{
					body_address = kernel::current_thread->address();
					THREAD_LOG("NtDuplicateObject: resolving NtCurrentThread pseudo-handle -> body 0x{:X}", body_address);
				}
				else
				{
					const auto entry = kernel::object_manager->lookup_handle(
						static_cast<object_manager_t::handle_type>(source_handle));

					if (entry)
					{
						body_address = entry->body_address;
						access = entry->access;
					}
				}

				if (!(options & duplicate_same_access) && desired_access != 0)
				{
					access = desired_access;
				}

				std::uint64_t new_handle = 0;

				if (body_address)
				{
					kernel::object_manager->reference_object(body_address);
					new_handle = kernel::object_manager->create_handle(body_address, access);
					THREAD_LOG("NtDuplicateObject: duplicated 0x{:X} -> 0x{:X}", source_handle, new_handle);
				}
				else
				{
					new_handle = source_handle;
					THREAD_WARN_LOG("NtDuplicateObject: source handle 0x{:X} not found, returning same value", source_handle);
				}

				static_cast<void>(emulator->write_virtual_memory(target_handle_out, &new_handle, sizeof(new_handle)));
			}

			if (options & duplicate_close_source)
			{
				kernel::object_manager->close_handle(static_cast<object_manager_t::handle_type>(source_handle));
				THREAD_LOG("NtDuplicateObject: closed source handle 0x{:X} (DUPLICATE_CLOSE_SOURCE)", source_handle);
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtDuplicateObject"
	);

	// NtTerminateProcess(ProcessHandle, ExitStatus)
	redirect_function(
		kernel::function_implementation_t(
			[emulator](bool& skip_return)
			{
				skip_return = true;

				const auto process_handle = emulator->read_register<x86::reg::rcx, std::uint64_t>();
				const auto exit_status = emulator->read_register<x86::reg::rdx, std::uint32_t>();

				THREAD_LOG("NtTerminateProcess called (handle=0x{:X}, status=0x{:X})", process_handle, exit_status);

				emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(0));
				emulator->write_register<x86::reg::rip>(0xFFFFFFFFFFFFFFFF);
			}
		),
		mapped_image,
		"NtTerminateProcess"
	);

	// NtRaiseException(ExceptionRecord*, Context*, FirstChance)
	redirect_function(
		kernel::function_implementation_t(
			[emulator](bool& skip_return)
			{
				skip_return = true;

				const auto exception_record_ptr = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
				const auto context_record_ptr = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
				const auto first_chance = emulator->read_register<x86::reg::r8, std::uint32_t>();

				std::uint32_t exception_code = 0;
				static_cast<void>(emulator->read_virtual_memory(exception_record_ptr, &exception_code, sizeof(exception_code)));

				THREAD_LOG("NtRaiseException called (record=0x{:X}, context=0x{:X}, first_chance={}, code=0x{:X})",
					exception_record_ptr, context_record_ptr, first_chance, exception_code);

				const bool is_usermode = kernel::current_thread && kernel::current_thread->state().is_usermode;

				if (!is_usermode)
				{
					emulator_t::address_type exception_address = 0;
					static_cast<void>(emulator->read_virtual_memory(
						exception_record_ptr + offsetof(EXCEPTION_RECORD, ExceptionAddress),
						&exception_address, sizeof(exception_address)));

					THREAD_LOG("NtRaiseException: kernel mode, dispatching via handle_exception (address=0x{:X})", exception_address);

					const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
					emulator->write_register<x86::reg::rsp>(rsp + 8);

					if (!kernel::handle_exception(emulator, exception_address, exception_code, 0, false))
					{
						THREAD_ERR_LOG("NtRaiseException: unhandled kernel exception 0x{:X}", exception_code);
					}

					return;
				}

				if (!user::ki_user_exception_dispatcher_address)
				{
					THREAD_ERR_LOG("NtRaiseException: KiUserExceptionDispatcher not resolved, terminating");
					emulator->write_register<x86::reg::rip>(0xFFFFFFFFFFFFFFFF);
					return;
				}

				EXCEPTION_RECORD er{};
				static_cast<void>(emulator->read_virtual_memory(exception_record_ptr, &er, sizeof(er)));

				constexpr std::size_t ctx_size = 0x4F0;
				std::vector<std::uint8_t> ctx_buf(ctx_size, 0);
				static_cast<void>(emulator->read_virtual_memory(context_record_ptr, ctx_buf.data(),
					std::min(ctx_size, static_cast<std::size_t>(sizeof(CONTEXT)))));

				const auto current_rsp = emulator->read_register<x86::reg::rsp, std::uint64_t>();
				const auto combined_size = (ctx_size + sizeof(EXCEPTION_RECORD) + 0xF) & ~static_cast<std::size_t>(0xF);
				constexpr std::size_t machine_frame_reserved = 0x40;
				const auto total_alloc = combined_size + machine_frame_reserved;
				const auto new_sp = (current_rsp - total_alloc) & ~static_cast<std::uint64_t>(0xFF);

				const auto zero_size = current_rsp - new_sp;
				std::vector<std::uint8_t> frame(zero_size, 0);

				std::memcpy(frame.data(), ctx_buf.data(), ctx_size);
				std::memcpy(frame.data() + ctx_size, &er, sizeof(er));

				static_cast<void>(emulator->write_virtual_memory(new_sp, frame.data(), zero_size));

				emulator->write_register<x86::reg::rsp>(new_sp);
				emulator->write_register<x86::reg::rip>(user::ki_user_exception_dispatcher_address);

				kernel::swap_to_usermode_segments(emulator);

				if (kernel::current_thread)
				{
					const auto gs_base = kernel::current_thread->state().gs_base;
					if (gs_base)
					{
						kernel::swap_to_usermode_gs(emulator, gs_base);
					}
				}

				user::clear_exception_dispatch_guard();

				THREAD_LOG("NtRaiseException: dispatching to KiUserExceptionDispatcher (code=0x{:08X}, rsp=0x{:X})",
					exception_code, new_sp);
			}
		),
		mapped_image,
		"NtRaiseException"
	);

	// NtRaiseHardError(ErrorStatus, NumberOfParameters, UnicodeStringParameterMask, Parameters, ValidResponseOptions, Response)
	redirect_function(
		[emulator]
		{
			const auto error_status = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto num_params = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto unicode_mask = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto params_array = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			THREAD_ERR_LOG("NtRaiseHardError called (status=0x{:X}, params={}, unicode_mask=0x{:X})",
				error_status, num_params, unicode_mask);

			if (params_array && num_params > 0)
			{
				for (std::uint32_t i = 0; i < num_params; ++i)
				{
					emulator_t::address_type param_value = 0;
					static_cast<void>(emulator->read_virtual_memory(
						params_array + i * sizeof(emulator_t::address_type), &param_value, sizeof(param_value)));

					if ((unicode_mask >> i) & 1)
					{
						const auto us = emulator_object_t<UNICODE_STRING>::view_at(emulator, param_value).read();
						const auto buf = reinterpret_cast<emulator_t::address_type>(us.Buffer);

						if (buf && us.Length)
						{
							const auto str = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buf));
							THREAD_ERR_LOG("NtRaiseHardError param[{}] (string): '{}'", i, str);
						}
					}
					else
					{
						THREAD_ERR_LOG("NtRaiseHardError param[{}]: 0x{:X}", i, param_value);
					}
				}
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtRaiseHardError"
	);

	// NtSetEvent(EventHandle, PreviousState)
	redirect_function(
		[emulator]
		{
			const auto event_handle = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto prev_state_out = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("NtSetEvent called (handle=0x{:X})", event_handle);

			if (prev_state_out)
			{
				constexpr std::int32_t zero = 0;
				static_cast<void>(emulator->write_virtual_memory(prev_state_out, &zero, sizeof(zero)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtSetEvent"
	);

	// NtWaitForSingleObject(Handle, Alertable, Timeout)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto alertable = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto timeout_ptr = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			THREAD_LOG("NtWaitForSingleObject called (handle=0x{:X}, alertable={}, timeout=0x{:X})",
				handle, alertable, timeout_ptr);

			write_nt_success(emulator);
		},
		mapped_image,
		"NtWaitForSingleObject"
	);

	// NtTraceEvent(...)
	redirect_function(
		[emulator]
		{
			THREAD_LOG("NtTraceEvent called (stub)");
			write_nt_success(emulator);
		},
		mapped_image,
		"NtTraceEvent"
	);

	// NtCreateIoCompletion(IoCompletionHandle*, DesiredAccess, ObjectAttributes*, NumberOfConcurrentThreads)
	redirect_function(
		[emulator]
		{
			const auto handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();

			THREAD_LOG("NtCreateIoCompletion called (handle_out=0x{:X}, access=0x{:X})",
				handle_out, desired_access);

			constexpr std::size_t body_size = 0x40;
			std::array<std::uint8_t, body_size> body{};

			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size());
			const auto handle = kernel::object_manager->create_handle(body_address, desired_access);

			if (handle_out)
			{
				static_cast<void>(emulator->write_virtual_memory(handle_out, &handle, sizeof(handle)));
			}

			THREAD_LOG("NtCreateIoCompletion: created handle 0x{:X}", handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtCreateIoCompletion"
	);

	// NtSetIoCompletion(IoCompletionHandle, KeyContext, ApcContext, IoStatus, IoStatusInformation)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();

			THREAD_LOG("NtSetIoCompletion called (handle=0x{:X})", handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtSetIoCompletion"
	);

	// NtSetIoCompletionEx(IoCompletionHandle, IoCompletionPacketHandle, KeyContext, ApcContext, IoStatus, IoStatusInformation)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();

			THREAD_LOG("NtSetIoCompletionEx called (handle=0x{:X})", handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtSetIoCompletionEx"
	);

	// NtRemoveIoCompletion(IoCompletionHandle, KeyContext*, ApcContext*, IoStatusBlock*, Timeout*)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();

			THREAD_LOG("NtRemoveIoCompletion called (handle=0x{:X}, returning STATUS_TIMEOUT)", handle);
			write_nt_status(emulator, 0x00000102); // STATUS_TIMEOUT
		},
		mapped_image,
		"NtRemoveIoCompletion"
	);

	// NtRemoveIoCompletionEx(IoCompletionHandle, IoCompletionInformation, Count, NumEntriesRemoved*, Timeout*, Alertable)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
			emulator_t::address_type num_entries_removed_ptr = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &num_entries_removed_ptr, sizeof(num_entries_removed_ptr)));

			THREAD_LOG("NtRemoveIoCompletionEx called (handle=0x{:X}, returning STATUS_TIMEOUT)", handle);

			if (num_entries_removed_ptr)
			{
				std::uint32_t zero = 0;
				static_cast<void>(emulator->write_virtual_memory(num_entries_removed_ptr, &zero, sizeof(zero)));
			}

			write_nt_status(emulator, 0x00000102); // STATUS_TIMEOUT
		},
		mapped_image,
		"NtRemoveIoCompletionEx"
	);

	// NtCancelWaitCompletionPacket(WaitCompletionPacketHandle, RemoveSignaledPacket)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();

			THREAD_LOG("NtCancelWaitCompletionPacket called (handle=0x{:X})", handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtCancelWaitCompletionPacket"
	);

	// NtCreateWaitCompletionPacket(WaitCompletionPacketHandle*, DesiredAccess, ObjectAttributes*)
	redirect_function(
		[emulator]
		{
			const auto handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();

			THREAD_LOG("NtCreateWaitCompletionPacket called (handle_out=0x{:X}, access=0x{:X})",
				handle_out, desired_access);

			constexpr std::size_t body_size = 0x10;
			std::array<std::uint8_t, body_size> body{};

			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size());
			const auto handle = kernel::object_manager->create_handle(body_address, desired_access);

			if (handle_out)
			{
				static_cast<void>(emulator->write_virtual_memory(handle_out, &handle, sizeof(handle)));
			}

			THREAD_LOG("NtCreateWaitCompletionPacket: created handle 0x{:X}", handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtCreateWaitCompletionPacket"
	);

	// NtAssociateWaitCompletionPacket(WaitCompletionPacketHandle, IoCompletionHandle, TargetObjectHandle, KeyContext, ApcContext, IoStatus, IoStatusInformation, AlreadySignaled*)
	redirect_function(
		[emulator]
		{
			THREAD_LOG("NtAssociateWaitCompletionPacket called (stub)");
			write_nt_success(emulator);
		},
		mapped_image,
		"NtAssociateWaitCompletionPacket"
	);

	// NtCreateWorkerFactory(WorkerFactoryHandle*, DesiredAccess, ObjectAttributes*, IoCompletionHandle, WorkerProcessHandle, StartRoutine, StartParameter, MaxThreadCount, StackReserve, StackCommit)
	redirect_function(
		[emulator]
		{
			const auto handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type start_routine = 0;
			std::uint32_t max_thread_count = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &start_routine, sizeof(start_routine)));
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x40, &max_thread_count, sizeof(max_thread_count)));

			THREAD_LOG("NtCreateWorkerFactory called (handle_out=0x{:X}, access=0x{:X}, start=0x{:X}, max_threads={})",
				handle_out, desired_access, start_routine, max_thread_count);

			constexpr std::size_t body_size = 0x80;
			std::array<std::uint8_t, body_size> body{};

			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size());
			const auto handle = kernel::object_manager->create_handle(body_address, desired_access);

			if (handle_out)
			{
				static_cast<void>(emulator->write_virtual_memory(handle_out, &handle, sizeof(handle)));
			}

			THREAD_LOG("NtCreateWorkerFactory: created handle 0x{:X}", handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtCreateWorkerFactory"
	);

	// NtSetInformationWorkerFactory(WorkerFactoryHandle, InfoClass, Buffer, BufferLength)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto info_class = emulator->read_register<x86::reg::rdx, std::uint32_t>();

			THREAD_LOG("NtSetInformationWorkerFactory called (handle=0x{:X}, class=0x{:X})", handle, info_class);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtSetInformationWorkerFactory"
	);

	// NtWorkerFactoryWorkerReady(WorkerFactoryHandle)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();

			THREAD_LOG("NtWorkerFactoryWorkerReady called (handle=0x{:X})", handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtWorkerFactoryWorkerReady"
	);

	// NtQueryInformationWorkerFactory(WorkerFactoryHandle, InfoClass, Buffer, BufferLength, ReturnLength*)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto info_class = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto buffer = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto buffer_length = emulator->read_register<x86::reg::r9, std::uint32_t>();

			THREAD_LOG("NtQueryInformationWorkerFactory called (handle=0x{:X}, class=0x{:X}, buf=0x{:X}, len=0x{:X})",
				handle, info_class, buffer, buffer_length);

			if (buffer && buffer_length)
			{
				std::vector<std::uint8_t> zeroed(buffer_length, 0);
				static_cast<void>(emulator->write_virtual_memory(buffer, zeroed.data(), zeroed.size()));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtQueryInformationWorkerFactory"
	);

	// NtCreateTimer2(TimerHandle*, Reserved1, ObjectAttributes*, Attributes, DesiredAccess)
	redirect_function(
		[emulator]
		{
			const auto handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::r9, std::uint32_t>();

			THREAD_LOG("NtCreateTimer2 called (handle_out=0x{:X})", handle_out);

			constexpr std::size_t body_size = 0x20;
			std::array<std::uint8_t, body_size> body{};

			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size());
			const auto handle = kernel::object_manager->create_handle(body_address, desired_access);

			if (handle_out)
			{
				static_cast<void>(emulator->write_virtual_memory(handle_out, &handle, sizeof(handle)));
			}

			THREAD_LOG("NtCreateTimer2: created handle 0x{:X}", handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtCreateTimer2"
	);

	// NtSetTimer2(TimerHandle, DueTime, Period, Parameters)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();

			THREAD_LOG("NtSetTimer2 called (handle=0x{:X})", handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtSetTimer2"
	);

	// NtCancelTimer2(TimerHandle, Parameters)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();

			THREAD_LOG("NtCancelTimer2 called (handle=0x{:X})", handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtCancelTimer2"
	);

	// NtShutdownWorkerFactory(WorkerFactoryHandle, PendingWorkerCount*)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto pending_count_ptr = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("NtShutdownWorkerFactory called (handle=0x{:X})", handle);

			if (pending_count_ptr)
			{
				std::int32_t zero = 0;
				static_cast<void>(emulator->write_virtual_memory(pending_count_ptr, &zero, sizeof(zero)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtShutdownWorkerFactory"
	);

	// NtReleaseWorkerFactoryWorker(WorkerFactoryHandle)
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();

			THREAD_LOG("NtReleaseWorkerFactoryWorker called (handle=0x{:X})", handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtReleaseWorkerFactoryWorker"
	);

	// NtTraceControl(FunctionCode, InBuffer, InBufferLen, OutBuffer, OutBufferLen, ReturnLength*)
	redirect_function(
		[emulator]
		{
			const auto function_code = emulator->read_register<x86::reg::rcx, std::uint32_t>();

			THREAD_LOG("NtTraceControl called (function=0x{:X})", function_code);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtTraceControl"
	);

	// NtQuerySecurityAttributesToken(TokenHandle, Attributes, NumAttributes, Buffer, Length, ReturnLength*)
	redirect_function(
		[emulator]
		{
			const auto token_handle = emulator->read_register<x86::reg::rcx, std::uint64_t>();

			THREAD_LOG("NtQuerySecurityAttributesToken called (token=0x{:X})", token_handle);
			write_nt_status(emulator, 0xC0000225); // STATUS_NOT_FOUND
		},
		mapped_image,
		"NtQuerySecurityAttributesToken"
	);

	// NtSetInformationVirtualMemory(ProcessHandle, InfoClass, NumberOfEntries, AddressEntries, VirtualMemoryInformationBuffer, VirtualMemoryInformationLength)
	redirect_function(
		[emulator]
		{
			const auto info_class = static_cast<std::uint32_t>(read_raw_arg(emulator, 1));
			THREAD_LOG("NtSetInformationVirtualMemory called (class=0x{:X}, stub)", info_class);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtSetInformationVirtualMemory"
	);

	// NtQueryWnfStateNameInformation(...)
	redirect_function(
		[emulator]
		{
			THREAD_LOG("NtQueryWnfStateNameInformation called (stub)");
			write_nt_status(emulator, 0xC0000225); // STATUS_NOT_FOUND
		},
		mapped_image,
		"NtQueryWnfStateNameInformation"
	);

	// NtAlpcConnectPort(PortHandle*, PortName, ObjectAttributes, PortAttributes, Flags, RequiredServerSid, ConnectionMessage, BufferLength, OutMessageAttributes, InMessageAttributes, Timeout)
	redirect_function(
		[emulator]
		{
			const auto port_handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto port_name_addr = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			std::string port_name;

			if (port_name_addr)
			{
				const auto us = emulator_object_t<UNICODE_STRING>::view_at(emulator, port_name_addr).read();
				const auto buffer_address = reinterpret_cast<emulator_t::address_type>(us.Buffer);

				if (buffer_address && us.Length)
				{
					port_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
				}
			}

			THREAD_LOG("NtAlpcConnectPort called (handle_out=0x{:X}, port='{}')", port_handle_out, port_name);

			constexpr std::size_t alpc_port_body_size = 0x20;
			std::array<std::uint8_t, alpc_port_body_size> body{};
			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size());
			const auto port_handle = kernel::object_manager->create_handle(body_address, 0x1F0001);

			if (port_handle_out)
			{
				static_cast<void>(emulator->write_virtual_memory(port_handle_out, &port_handle, sizeof(port_handle)));
			}

			THREAD_LOG("NtAlpcConnectPort: created dummy handle 0x{:X}", port_handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtAlpcConnectPort"
	);

	// NtAlpcSendWaitReceivePort(PortHandle, Flags, SendMessage, SendMessageAttributes, ReceiveMessage, BufferLength, ReceiveMessageAttributes, Timeout)
	redirect_function(
		[emulator]
		{
			const auto port_handle = emulator->read_register<x86::reg::rcx, std::uint64_t>();

			THREAD_LOG("NtAlpcSendWaitReceivePort called (handle=0x{:X}, stub)", port_handle);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtAlpcSendWaitReceivePort"
	);

	// NtApphelpCacheControl(Command, Data)
	redirect_function(
		[emulator]
		{
			const auto command = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto data = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("NtApphelpCacheControl called (command=0x{:X}, data=0x{:X}, stub)", command, data);
			write_nt_success(emulator);
		},
		mapped_image,
		"NtApphelpCacheControl"
	);

	// NtConnectPort(PortHandle, PortName, SecurityQos, ClientView, ServerView, MaxMessageLength, ConnectionInfo, ConnectionInfoLength)
	redirect_function(
		[emulator]
		{
			const auto port_handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto port_name_ptr = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto client_view_ptr = emulator->read_register<x86::reg::r9, emulator_t::address_type>();
			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			std::string port_name;
			if (port_name_ptr)
			{
				auto us_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, port_name_ptr);
				const auto us = us_object.read();
				const auto buffer_address = reinterpret_cast<emulator_t::address_type>(us.Buffer);

				if (buffer_address && us.Length > 0)
				{
					const auto char_count = us.Length / sizeof(wchar_t);
					std::wstring wide_name(char_count, L'\0');
					emulator->read_virtual_memory(buffer_address, wide_name.data(), us.Length)
						.throw_if("NtConnectPort: read port name");
					port_name = util::narrow_wstring(wide_name);
				}
			}

			emulator_t::address_type server_view_ptr = 0;
			emulator->read_virtual_memory(rsp + 0x28, &server_view_ptr, sizeof(server_view_ptr)).throw_if("NtConnectPort: read ServerView ptr");

			emulator_t::address_type max_msg_len_ptr = 0;
			emulator->read_virtual_memory(rsp + 0x30, &max_msg_len_ptr, sizeof(max_msg_len_ptr)).throw_if("NtConnectPort: read MaxMessageLength ptr");

			emulator_t::address_type connection_info_ptr = 0;
			emulator->read_virtual_memory(rsp + 0x38, &connection_info_ptr, sizeof(connection_info_ptr)).throw_if("NtConnectPort: read ConnectionInfo ptr");

			emulator_t::address_type connection_info_len_ptr = 0;
			emulator->read_virtual_memory(rsp + 0x40, &connection_info_len_ptr, sizeof(connection_info_len_ptr)).throw_if("NtConnectPort: read ConnectionInfoLength ptr");

			THREAD_LOG("NtConnectPort called (handle_out=0x{:X}, name='{}', client_view=0x{:X}, conn_info=0x{:X})",
				port_handle_out, port_name, client_view_ptr, connection_info_ptr);

			if (port_handle_out)
			{
				const auto dummy_handle = static_cast<object_manager_t::handle_type>(0xDEAD0001);
				emulator->write_virtual_memory(port_handle_out, &dummy_handle, sizeof(dummy_handle))
					.throw_if("NtConnectPort: write handle");
			}

			if (client_view_ptr)
			{
				struct port_view64
				{
					std::uint32_t length;
					std::uint32_t pad0;
					std::uint64_t section_handle;
					std::uint32_t section_offset;
					std::uint32_t pad1;
					std::int64_t view_size;
					std::uint64_t view_base;
					std::uint64_t view_remote_base;
				};

				port_view64 view{};
				emulator->read_virtual_memory(client_view_ptr, &view, sizeof(view))
					.throw_if("NtConnectPort: read client view");

				if (view.view_size > 0)
				{
					const auto alloc_size = static_cast<emulator_t::size_type>(view.view_size);
					emulator_t::address_type view_base = 0;

					if (user::memory_manager)
					{
						auto region = alloc_size;
						user::memory_manager->allocate(view_base, region, 0x3000, 0x04);
					}
					else
					{
						const auto result = emulator->heap_allocate(alloc_size, prot_read_write, true);
						if (result)
						{
							view_base = *result;
						}
					}

					if (view_base)
					{
						view.view_base = view_base;
						view.view_remote_base = view_base;
						emulator->write_virtual_memory(client_view_ptr, &view, sizeof(view))
							.throw_if("NtConnectPort: write client view");

						THREAD_LOG("NtConnectPort: allocated client view at 0x{:X} (size=0x{:X})", view_base, alloc_size);
					}
				}
			}

			if (server_view_ptr)
			{
				struct remote_port_view
				{
					std::uint32_t length;
					std::uint32_t pad0;
					std::int64_t view_size;
					emulator_t::address_type view_base;
				};

				remote_port_view view{};
				emulator->read_virtual_memory(server_view_ptr, &view, sizeof(view))
					.throw_if("NtConnectPort: read server view");

				if (view.length >= sizeof(remote_port_view))
				{
					view.view_size = 0x10000;
					view.view_base = 0;
					emulator->write_virtual_memory(server_view_ptr, &view, sizeof(view))
						.throw_if("NtConnectPort: write server view");
				}
			}

			if (max_msg_len_ptr)
			{
				const std::uint32_t max_msg = 0x148;
				emulator->write_virtual_memory(max_msg_len_ptr, &max_msg, sizeof(max_msg))
					.throw_if("NtConnectPort: write MaxMessageLength");
			}

			if (connection_info_ptr && connection_info_len_ptr)
			{
				std::uint32_t conn_info_len = 0;
				emulator->read_virtual_memory(connection_info_len_ptr, &conn_info_len, sizeof(conn_info_len))
					.throw_if("NtConnectPort: read connection info length");

				if (conn_info_len > 0 && conn_info_len < 0x10000)
				{
					std::vector<std::uint8_t> zeroed(conn_info_len, 0);
					emulator->write_virtual_memory(connection_info_ptr, zeroed.data(), zeroed.size())
						.throw_if("NtConnectPort: zero connection info");
				}
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtConnectPort"
	);

	// NtSecureConnectPort(PortHandle, PortName, SecurityQos, ClientView, RequiredServerSid, ServerView, MaxMessageLength, ConnectionInfo, ConnectionInfoLength)
	redirect_function(
		[emulator]
		{
			const auto port_handle_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto port_name_ptr = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto client_view_ptr = emulator->read_register<x86::reg::r9, emulator_t::address_type>();
			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			std::string port_name;
			if (port_name_ptr)
			{
				auto us_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, port_name_ptr);
				const auto us = us_object.read();
				const auto buffer_address = reinterpret_cast<emulator_t::address_type>(us.Buffer);

				if (buffer_address && us.Length > 0)
				{
					const auto char_count = us.Length / sizeof(wchar_t);
					std::wstring wide_name(char_count, L'\0');
					emulator->read_virtual_memory(buffer_address, wide_name.data(), us.Length)
						.throw_if("NtSecureConnectPort: read port name");
					port_name = util::narrow_wstring(wide_name);
				}
			}

			emulator_t::address_type server_view_ptr = 0;
			emulator->read_virtual_memory(rsp + 0x30, &server_view_ptr, sizeof(server_view_ptr)).throw_if("NtSecureConnectPort: read ServerView ptr");

			emulator_t::address_type max_msg_len_ptr = 0;
			emulator->read_virtual_memory(rsp + 0x38, &max_msg_len_ptr, sizeof(max_msg_len_ptr)).throw_if("NtSecureConnectPort: read MaxMessageLength ptr");

			emulator_t::address_type connection_info_ptr = 0;
			emulator->read_virtual_memory(rsp + 0x40, &connection_info_ptr, sizeof(connection_info_ptr)).throw_if("NtSecureConnectPort: read ConnectionInfo ptr");

			emulator_t::address_type connection_info_len_ptr = 0;
			emulator->read_virtual_memory(rsp + 0x48, &connection_info_len_ptr, sizeof(connection_info_len_ptr)).throw_if("NtSecureConnectPort: read ConnectionInfoLength ptr");

			THREAD_LOG("NtSecureConnectPort called (handle_out=0x{:X}, name='{}', client_view=0x{:X}, conn_info=0x{:X})",
				port_handle_out, port_name, client_view_ptr, connection_info_ptr);

			if (port_handle_out)
			{
				const auto dummy_handle = static_cast<object_manager_t::handle_type>(0xDEAD0002);
				emulator->write_virtual_memory(port_handle_out, &dummy_handle, sizeof(dummy_handle))
					.throw_if("NtSecureConnectPort: write handle");
			}

			if (client_view_ptr)
			{
				struct port_view64
				{
					std::uint32_t length;
					std::uint32_t pad0;
					std::uint64_t section_handle;
					std::uint32_t section_offset;
					std::uint32_t pad1;
					std::int64_t view_size;
					std::uint64_t view_base;
					std::uint64_t view_remote_base;
				};

				port_view64 view{};
				emulator->read_virtual_memory(client_view_ptr, &view, sizeof(view))
					.throw_if("NtSecureConnectPort: read client view");

				if (view.view_size > 0)
				{
					const auto alloc_size = static_cast<emulator_t::size_type>(view.view_size);
					emulator_t::address_type view_base = 0;

					if (user::memory_manager)
					{
						auto region = alloc_size;
						user::memory_manager->allocate(view_base, region, 0x3000, 0x04);
					}
					else
					{
						const auto result = emulator->heap_allocate(alloc_size, prot_read_write, true);
						if (result)
						{
							view_base = *result;
						}
					}

					if (view_base)
					{
						view.view_base = view_base;
						view.view_remote_base = view_base;
						emulator->write_virtual_memory(client_view_ptr, &view, sizeof(view))
							.throw_if("NtSecureConnectPort: write client view");

						THREAD_LOG("NtSecureConnectPort: allocated client view at 0x{:X} (size=0x{:X})", view_base, alloc_size);
					}
				}
			}

			if (server_view_ptr)
			{
				struct remote_port_view
				{
					std::uint32_t length;
					std::uint32_t pad0;
					std::int64_t view_size;
					emulator_t::address_type view_base;
				};

				remote_port_view view{};
				emulator->read_virtual_memory(server_view_ptr, &view, sizeof(view))
					.throw_if("NtSecureConnectPort: read server view");

				if (view.length >= sizeof(remote_port_view))
				{
					view.view_size = 0x10000;
					view.view_base = 0;
					emulator->write_virtual_memory(server_view_ptr, &view, sizeof(view))
						.throw_if("NtSecureConnectPort: write server view");
				}
			}

			if (max_msg_len_ptr)
			{
				const std::uint32_t max_msg = 0x148;
				emulator->write_virtual_memory(max_msg_len_ptr, &max_msg, sizeof(max_msg))
					.throw_if("NtSecureConnectPort: write MaxMessageLength");
			}

			if (connection_info_ptr && connection_info_len_ptr)
			{
				std::uint32_t conn_info_len = 0;
				emulator->read_virtual_memory(connection_info_len_ptr, &conn_info_len, sizeof(conn_info_len))
					.throw_if("NtSecureConnectPort: read connection info length");

				if (conn_info_len > 0 && conn_info_len < 0x10000)
				{
					std::vector<std::uint8_t> zeroed(conn_info_len, 0);
					emulator->write_virtual_memory(connection_info_ptr, zeroed.data(), zeroed.size())
						.throw_if("NtSecureConnectPort: zero connection info");
				}
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"NtSecureConnectPort"
	);

	redirect_function(
		[emulator]
		{
			const auto base_address_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto default_locale_out = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("NtInitializeNlsFiles called (base_out=0x{:X}, locale_out=0x{:X})",
				base_address_out, default_locale_out);

			const auto file = kernel::filesystem->open_at("system32/locale.nls");

			if (!file)
			{
				THREAD_WARN_LOG("NtInitializeNlsFiles: locale.nls not found in VFS");
				constexpr std::uint32_t status_file_invalid = 0xC0000098;
				write_nt_status(emulator, status_file_invalid);
				return;
			}

			const auto data = file->read();
			const auto alloc_size = (data.size() + 0xFFF) & ~static_cast<std::size_t>(0xFFF);
			const auto base = user::memory_manager->allocate_pages(alloc_size);

			if (!base)
			{
				THREAD_WARN_LOG("NtInitializeNlsFiles: failed to allocate {} bytes", alloc_size);
				constexpr std::uint32_t status_no_memory = 0xC0000017;
				write_nt_status(emulator, status_no_memory);
				return;
			}

			static_cast<void>(emulator->write_virtual_memory(base, data.data(), data.size()));
			static_cast<void>(emulator->write_virtual_memory(base_address_out, &base, sizeof(base)));

			constexpr std::uint32_t default_locale = 0x0409;
			static_cast<void>(emulator->write_virtual_memory(default_locale_out, &default_locale, sizeof(default_locale)));

			THREAD_LOG("NtInitializeNlsFiles: loaded locale.nls ({} bytes) at 0x{:X}", data.size(), base);

			write_nt_success(emulator);
		},
		mapped_image,
		"NtInitializeNlsFiles"
	);

	redirect_function(
		[emulator]
		{
			const auto section_type = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto section_data = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto context_data = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto section_pointer_out = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
			emulator_t::address_type section_size_out = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &section_size_out, sizeof(section_size_out)));

			THREAD_LOG("NtGetNlsSectionPtr called (type={}, data={}, context=0x{:X}, ptr_out=0x{:X}, size_out=0x{:X})",
				section_type, section_data, context_data, section_pointer_out, section_size_out);

			if (section_type != 11)
			{
				THREAD_WARN_LOG("NtGetNlsSectionPtr: unsupported section type {}", section_type);
				constexpr std::uint32_t status_not_supported = 0xC00000BB;
				write_nt_status(emulator, status_not_supported);
				return;
			}

			const auto path = "system32/c_" + std::to_string(section_data) + ".nls";
			const auto file = kernel::filesystem->open_at(path);

			if (!file)
			{
				THREAD_WARN_LOG("NtGetNlsSectionPtr: {} not found in VFS", path);
				constexpr std::uint32_t status_object_name_not_found = 0xC0000034;
				write_nt_status(emulator, status_object_name_not_found);
				return;
			}

			const auto data = file->read();
			const auto alloc_size = (data.size() + 0xFFF) & ~static_cast<std::size_t>(0xFFF);
			const auto base = user::memory_manager->allocate_pages(alloc_size);

			if (!base)
			{
				THREAD_WARN_LOG("NtGetNlsSectionPtr: failed to allocate {} bytes for {}", alloc_size, path);
				constexpr std::uint32_t status_no_memory = 0xC0000017;
				write_nt_status(emulator, status_no_memory);
				return;
			}

			static_cast<void>(emulator->write_virtual_memory(base, data.data(), data.size()));

			if (section_pointer_out)
			{
				static_cast<void>(emulator->write_virtual_memory(section_pointer_out, &base, sizeof(base)));
			}

			if (section_size_out)
			{
				const auto size = static_cast<std::uint32_t>(alloc_size);
				static_cast<void>(emulator->write_virtual_memory(section_size_out, &size, sizeof(size)));
			}

			THREAD_LOG("NtGetNlsSectionPtr: loaded {} ({} bytes) at 0x{:X}", path, data.size(), base);

			write_nt_success(emulator);
		},
		mapped_image,
		"NtGetNlsSectionPtr"
	);
}
