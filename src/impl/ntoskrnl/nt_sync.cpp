#include "nt_sync.hpp"
#include "../../emulator/object.hpp"
#include "../../kernel/thread.hpp"
#include "../../util/util.hpp"

constexpr std::uint32_t status_success = 0x00000000;
constexpr std::uint32_t status_timeout = 0x00000102;
constexpr std::uint32_t status_invalid_handle = 0xC0000008;
constexpr std::uint32_t status_invalid_parameter = 0xC000000D;
constexpr std::uint32_t status_mutant_not_owned = 0xC0000046;
constexpr std::uint32_t status_semaphore_limit_exceeded = 0xC0000047;
constexpr std::uint32_t status_object_type_mismatch = 0xC0000024;

// NtCreateEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState)
static void handle_create_event(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes, std::uint32_t event_type,
	std::uint32_t initial_state)
{
	THREAD_LOG("NtCreateEvent called (handle_out=0x{:X}, access=0x{:X}, type={}, initial={})",
		handle_out, desired_access, event_type, initial_state);

	if (event_type > 1)
	{
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	const auto type = static_cast<event_object_t::type_t>(event_type);
	auto event = std::make_shared<event_object_t>(type, initial_state != 0);

	_KEVENT body = {};
	body.Header.Type = static_cast<std::uint8_t>(event_type);
	body.Header.SignalState = initial_state ? 1 : 0;

	const auto body_address = kernel::object_manager->create_object(0, &body, sizeof(body), event);
	const auto handle = kernel::object_manager->create_handle(body_address, desired_access);

	if (handle_out)
	{
		emulator_err_t error = emulator->write_virtual_memory(handle_out, &handle, sizeof(handle));
		error.throw_if("NtCreateEvent: write handle");
	}

	std::string name;
	if (object_attributes)
	{
		auto oa_obj = emulator_object_t<OBJECT_ATTRIBUTES>::view_at(emulator, object_attributes);
		const auto oa = oa_obj.read();
		const auto name_address = reinterpret_cast<emulator_t::address_type>(oa.ObjectName);

		if (name_address)
		{
			auto us_obj = emulator_object_t<UNICODE_STRING>::view_at(emulator, name_address);
			const auto us = us_obj.read();
			const auto buffer_address = reinterpret_cast<emulator_t::address_type>(us.Buffer);

			if (buffer_address && us.Length)
			{
				const auto wname = kernel::read_guest_wstring(*emulator, buffer_address);
				name = util::narrow_wstring(wname);
				kernel::object_manager->register_named_object(name, body_address);
			}
		}
	}

	THREAD_LOG("NtCreateEvent: created handle 0x{:X} (type={}, signaled={}, name='{}')",
		handle, event_type, initial_state, name);
	write_nt_success(emulator);
}

// NtSetEvent(HANDLE EventHandle, PLONG PreviousState)
static void handle_set_event(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type event_handle, emulator_t::address_type previous_state_ptr)
{
	THREAD_LOG("NtSetEvent called (handle=0x{:X}, previous_state=0x{:X})",
		event_handle, previous_state_ptr);

	const auto event = kernel::object_manager->get_object_from_handle<event_object_t>(event_handle);

	if (!event)
	{
		THREAD_WARN_LOG("NtSetEvent: invalid handle 0x{:X}", event_handle);
		write_nt_status(emulator, status_invalid_handle);
		return;
	}

	const std::int32_t previous = event->signaled ? 1 : 0;
	event->signaled = true;

	if (previous_state_ptr)
	{
		emulator_err_t error = emulator->write_virtual_memory(previous_state_ptr, &previous, sizeof(previous));
		error.throw_if("NtSetEvent: write previous state");
	}

	THREAD_LOG("NtSetEvent: handle 0x{:X} signaled (was {})", event_handle, previous);
	write_nt_success(emulator);
}

// NtClearEvent(HANDLE EventHandle)
static void handle_clear_event(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type event_handle)
{
	THREAD_LOG("NtClearEvent called (handle=0x{:X})", event_handle);

	const auto event = kernel::object_manager->get_object_from_handle<event_object_t>(event_handle);

	if (!event)
	{
		THREAD_WARN_LOG("NtClearEvent: invalid handle 0x{:X}", event_handle);
		write_nt_status(emulator, status_invalid_handle);
		return;
	}

	event->signaled = false;
	write_nt_success(emulator);
}

// NtResetEvent(HANDLE EventHandle, PLONG PreviousState)
static void handle_reset_event(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type event_handle, emulator_t::address_type previous_state_ptr)
{
	THREAD_LOG("NtResetEvent called (handle=0x{:X}, previous_state=0x{:X})",
		event_handle, previous_state_ptr);

	const auto event = kernel::object_manager->get_object_from_handle<event_object_t>(event_handle);

	if (!event)
	{
		THREAD_WARN_LOG("NtResetEvent: invalid handle 0x{:X}", event_handle);
		write_nt_status(emulator, status_invalid_handle);
		return;
	}

	const std::int32_t previous = event->signaled ? 1 : 0;
	event->signaled = false;

	if (previous_state_ptr)
	{
		emulator_err_t error = emulator->write_virtual_memory(previous_state_ptr, &previous, sizeof(previous));
		error.throw_if("NtResetEvent: write previous state");
	}

	THREAD_LOG("NtResetEvent: handle 0x{:X} cleared (was {})", event_handle, previous);
	write_nt_success(emulator);
}

// NtQueryEvent(HANDLE EventHandle, EVENT_INFORMATION_CLASS InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength)
static void handle_query_event(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type event_handle, std::uint32_t info_class,
	emulator_t::address_type buffer, std::uint32_t length,
	emulator_t::address_type return_length)
{
	THREAD_LOG("NtQueryEvent called (handle=0x{:X}, class={}, buffer=0x{:X}, length=0x{:X})",
		event_handle, info_class, buffer, length);

	if (info_class != 0)
	{
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	if (length < 8)
	{
		write_nt_status(emulator, 0xC0000004); // STATUS_INFO_LENGTH_MISMATCH
		return;
	}

	const auto event = kernel::object_manager->get_object_from_handle<event_object_t>(event_handle);

	if (!event)
	{
		write_nt_status(emulator, status_invalid_handle);
		return;
	}

	struct event_basic_information_t
	{
		std::uint32_t event_type;
		std::int32_t event_state;
	};

	event_basic_information_t info = {};
	info.event_type = static_cast<std::uint32_t>(event->event_type);
	info.event_state = event->signaled ? 1 : 0;

	emulator_err_t error = emulator->write_virtual_memory(buffer, &info, sizeof(info));
	error.throw_if("NtQueryEvent: write buffer");

	if (return_length)
	{
		const std::uint32_t written = 8;
		error = emulator->write_virtual_memory(return_length, &written, sizeof(written));
		error.throw_if("NtQueryEvent: write return length");
	}

	write_nt_success(emulator);
}

// NtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner)
static void handle_create_mutant(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes, std::uint32_t initial_owner)
{
	THREAD_LOG("NtCreateMutant called (handle_out=0x{:X}, access=0x{:X}, initial_owner={})",
		handle_out, desired_access, initial_owner);

	const auto tid = kernel::current_thread ? kernel::current_thread->id() : 0;
	auto mutant = std::make_shared<mutant_object_t>(initial_owner != 0, tid);

	std::uint8_t body[64] = {};
	const auto body_address = kernel::object_manager->create_object(0, body, sizeof(body), mutant);
	const auto handle = kernel::object_manager->create_handle(body_address, desired_access);

	if (handle_out)
	{
		emulator_err_t error = emulator->write_virtual_memory(handle_out, &handle, sizeof(handle));
		error.throw_if("NtCreateMutant: write handle");
	}

	THREAD_LOG("NtCreateMutant: created handle 0x{:X} (initial_owner={})", handle, initial_owner);
	write_nt_success(emulator);
}

// NtReleaseMutant(HANDLE MutantHandle, PLONG PreviousCount)
static void handle_release_mutant(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type mutant_handle, emulator_t::address_type previous_count_ptr)
{
	THREAD_LOG("NtReleaseMutant called (handle=0x{:X}, previous_count=0x{:X})",
		mutant_handle, previous_count_ptr);

	const auto mutant = kernel::object_manager->get_object_from_handle<mutant_object_t>(mutant_handle);

	if (!mutant)
	{
		write_nt_status(emulator, status_invalid_handle);
		return;
	}

	if (!mutant->owned)
	{
		write_nt_status(emulator, status_mutant_not_owned);
		return;
	}

	const std::int32_t previous = mutant->count;
	mutant->count--;

	if (mutant->count <= 0)
	{
		mutant->owned = false;
		mutant->owner_thread_id = 0;
		mutant->count = 0;
	}

	if (previous_count_ptr)
	{
		emulator_err_t error = emulator->write_virtual_memory(previous_count_ptr, &previous, sizeof(previous));
		error.throw_if("NtReleaseMutant: write previous count");
	}

	THREAD_LOG("NtReleaseMutant: handle 0x{:X} released (was {})", mutant_handle, previous);
	write_nt_success(emulator);
}

// NtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, LONG InitialCount, LONG MaximumCount)
static void handle_create_semaphore(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes, std::int32_t initial_count,
	std::int32_t maximum_count)
{
	THREAD_LOG("NtCreateSemaphore called (handle_out=0x{:X}, access=0x{:X}, initial={}, max={})",
		handle_out, desired_access, initial_count, maximum_count);

	if (maximum_count <= 0 || initial_count < 0 || initial_count > maximum_count)
	{
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	auto semaphore = std::make_shared<semaphore_object_t>(initial_count, maximum_count);

	std::uint8_t body[64] = {};
	const auto body_address = kernel::object_manager->create_object(0, body, sizeof(body), semaphore);
	const auto handle = kernel::object_manager->create_handle(body_address, desired_access);

	if (handle_out)
	{
		emulator_err_t error = emulator->write_virtual_memory(handle_out, &handle, sizeof(handle));
		error.throw_if("NtCreateSemaphore: write handle");
	}

	THREAD_LOG("NtCreateSemaphore: created handle 0x{:X} (initial={}, max={})",
		handle, initial_count, maximum_count);
	write_nt_success(emulator);
}

// NtReleaseSemaphore(HANDLE SemaphoreHandle, LONG ReleaseCount, PLONG PreviousCount)
static void handle_release_semaphore(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type sem_handle, std::int32_t release_count,
	emulator_t::address_type previous_count_ptr)
{
	THREAD_LOG("NtReleaseSemaphore called (handle=0x{:X}, count={}, previous=0x{:X})",
		sem_handle, release_count, previous_count_ptr);

	if (release_count <= 0)
	{
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	const auto semaphore = kernel::object_manager->get_object_from_handle<semaphore_object_t>(sem_handle);

	if (!semaphore)
	{
		write_nt_status(emulator, status_invalid_handle);
		return;
	}

	const std::int32_t previous = semaphore->count;

	if (semaphore->count + release_count > semaphore->max_count)
	{
		write_nt_status(emulator, status_semaphore_limit_exceeded);
		return;
	}

	semaphore->count += release_count;

	if (previous_count_ptr)
	{
		emulator_err_t error = emulator->write_virtual_memory(previous_count_ptr, &previous, sizeof(previous));
		error.throw_if("NtReleaseSemaphore: write previous count");
	}

	THREAD_LOG("NtReleaseSemaphore: handle 0x{:X} released {} (was {}, now {})",
		sem_handle, release_count, previous, semaphore->count);
	write_nt_success(emulator);
}

// NtCreateKeyedEvent(PHANDLE KeyedEventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Flags)
static void handle_create_keyed_event(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes, std::uint32_t flags)
{
	THREAD_LOG("NtCreateKeyedEvent called (handle_out=0x{:X}, access=0x{:X}, flags=0x{:X})",
		handle_out, desired_access, flags);

	if (flags != 0)
	{
		write_nt_status(emulator, 0xC0000192); // STATUS_INVALID_PARAMETER_4
		return;
	}

	auto keyed_event = std::make_shared<keyed_event_object_t>();

	std::uint8_t body[64] = {};
	const auto body_address = kernel::object_manager->create_object(0, body, sizeof(body), keyed_event);
	const auto handle = kernel::object_manager->create_handle(body_address, desired_access);

	if (handle_out)
	{
		emulator_err_t error = emulator->write_virtual_memory(handle_out, &handle, sizeof(handle));
		error.throw_if("NtCreateKeyedEvent: write handle");
	}

	THREAD_LOG("NtCreateKeyedEvent: created handle 0x{:X}", handle);
	write_nt_success(emulator);
}

// NtWaitForKeyedEvent(HANDLE KeyedEventHandle, PVOID Key, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
static void handle_wait_for_keyed_event(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type keyed_event_handle, emulator_t::address_type key,
	std::uint32_t alertable, emulator_t::address_type timeout_ptr)
{
	THREAD_LOG("NtWaitForKeyedEvent called (handle=0x{:X}, key=0x{:X}, alertable={}, timeout=0x{:X})",
		keyed_event_handle, key, alertable, timeout_ptr);

	// single-threaded emulation - keyed events complete immediately
	write_nt_success(emulator);
}

// NtReleaseKeyedEvent(HANDLE KeyedEventHandle, PVOID Key, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
static void handle_release_keyed_event(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type keyed_event_handle, emulator_t::address_type key,
	std::uint32_t alertable, emulator_t::address_type timeout_ptr)
{
	THREAD_LOG("NtReleaseKeyedEvent called (handle=0x{:X}, key=0x{:X}, alertable={}, timeout=0x{:X})",
		keyed_event_handle, key, alertable, timeout_ptr);

	write_nt_success(emulator);
}

// NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
static void handle_wait_for_single_object(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle, std::uint32_t alertable, emulator_t::address_type timeout_ptr)
{
	std::int64_t timeout_value = 0;
	bool has_timeout = false;

	if (timeout_ptr)
	{
		has_timeout = true;
		emulator_err_t error = emulator->read_virtual_memory(timeout_ptr, &timeout_value, sizeof(timeout_value));
		error.throw_if("NtWaitForSingleObject: read timeout");
	}

	THREAD_LOG("NtWaitForSingleObject called (handle=0x{:X}, alertable={}, timeout={})",
		handle, alertable, has_timeout ? timeout_value : -1);

	const auto event = kernel::object_manager->get_object_from_handle<event_object_t>(handle);

	if (event)
	{
		if (event->signaled)
		{
			if (event->event_type == event_object_t::synchronization)
			{
				event->signaled = false;
			}

			THREAD_LOG("NtWaitForSingleObject: event 0x{:X} already signaled", handle);
			write_nt_success(emulator);
			return;
		}

		if (has_timeout && timeout_value == 0)
		{
			THREAD_LOG("NtWaitForSingleObject: event 0x{:X} not signaled, timeout=0", handle);
			write_nt_status(emulator, status_timeout);
			return;
		}

		// non-zero timeout on unsignaled event - simulate short wait then succeed
		if (has_timeout && timeout_value < 0)
		{
			const auto ms = static_cast<std::uint64_t>(-timeout_value) / 10000;
			if (kernel::current_thread && ms > 0)
			{
				kernel::current_thread->sleep_for(std::chrono::milliseconds(ms > 100 ? 100 : ms));
			}
		}

		event->signaled = true;
		if (event->event_type == event_object_t::synchronization)
		{
			event->signaled = false;
		}

		write_nt_success(emulator);
		return;
	}

	const auto mutant = kernel::object_manager->get_object_from_handle<mutant_object_t>(handle);

	if (mutant)
	{
		const auto tid = kernel::current_thread ? kernel::current_thread->id() : 0;
		mutant->owned = true;
		mutant->owner_thread_id = tid;
		mutant->count++;

		THREAD_LOG("NtWaitForSingleObject: acquired mutant 0x{:X}", handle);
		write_nt_success(emulator);
		return;
	}

	const auto semaphore = kernel::object_manager->get_object_from_handle<semaphore_object_t>(handle);

	if (semaphore)
	{
		if (semaphore->count > 0)
		{
			semaphore->count--;
			THREAD_LOG("NtWaitForSingleObject: acquired semaphore 0x{:X} (count={})",
				handle, semaphore->count);
			write_nt_success(emulator);
			return;
		}

		if (has_timeout && timeout_value == 0)
		{
			write_nt_status(emulator, status_timeout);
			return;
		}

		semaphore->count = 0;
		write_nt_success(emulator);
		return;
	}

	const auto thread_obj = kernel::object_manager->get_object_from_handle<thread_object_t>(handle);

	if (thread_obj)
	{
		std::int32_t signal_state = 0;
		static_cast<void>(emulator->read_virtual_memory(
			thread_obj->thread->address() + offsetof(_KTHREAD, Header.SignalState),
			&signal_state, sizeof(signal_state)));

		if (signal_state != 0)
		{
			THREAD_LOG("NtWaitForSingleObject: thread {} already finished", thread_obj->thread->id());
			write_nt_success(emulator);
			return;
		}

		THREAD_LOG("NtWaitForSingleObject: waiting for thread {} to finish", thread_obj->thread->id());

		if (kernel::current_thread)
		{
			kernel::current_thread->sleep_for(std::chrono::milliseconds(1));
			write_nt_success(emulator);
			kernel::switch_thread(emulator, false, true);
			return;
		}

		write_nt_success(emulator);
		return;
	}

	THREAD_WARN_LOG("NtWaitForSingleObject: unknown object type for handle 0x{:X}", handle);
	write_nt_success(emulator);
}

// NtWaitForMultipleObjects(ULONG Count, HANDLE* Handles, WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
static void handle_wait_for_multiple_objects(const std::shared_ptr<emulator_t>& emulator,
	std::uint32_t count, emulator_t::address_type handles_ptr,
	std::uint32_t wait_type, std::uint32_t alertable,
	emulator_t::address_type timeout_ptr)
{
	THREAD_LOG("NtWaitForMultipleObjects called (count={}, handles=0x{:X}, wait_type={}, alertable={}, timeout=0x{:X})",
		count, handles_ptr, wait_type, alertable, timeout_ptr);

	if (count == 0 || count > 64 || !handles_ptr)
	{
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	std::vector<emulator_t::address_type> handles(count);
	emulator_err_t error = emulator->read_virtual_memory(handles_ptr, handles.data(),
		count * sizeof(emulator_t::address_type));
	error.throw_if("NtWaitForMultipleObjects: read handles");

	// single-threaded - signal all waitable events and return
	for (std::uint32_t i = 0; i < count; ++i)
	{
		const auto event = kernel::object_manager->get_object_from_handle<event_object_t>(handles[i]);

		if (event && event->signaled && event->event_type == event_object_t::synchronization)
		{
			event->signaled = false;
		}
	}

	write_nt_success(emulator);
}

// NtSignalAndWaitForSingleObject(HANDLE SignalHandle, HANDLE WaitHandle, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
static void handle_signal_and_wait(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type signal_handle, emulator_t::address_type wait_handle,
	std::uint32_t alertable, emulator_t::address_type timeout_ptr)
{
	THREAD_LOG("NtSignalAndWaitForSingleObject called (signal=0x{:X}, wait=0x{:X}, alertable={}, timeout=0x{:X})",
		signal_handle, wait_handle, alertable, timeout_ptr);

	const auto signal_event = kernel::object_manager->get_object_from_handle<event_object_t>(signal_handle);

	if (signal_event)
	{
		signal_event->signaled = true;
	}

	const auto signal_semaphore = kernel::object_manager->get_object_from_handle<semaphore_object_t>(signal_handle);

	if (signal_semaphore && signal_semaphore->count < signal_semaphore->max_count)
	{
		signal_semaphore->count++;
	}

	const auto signal_mutant = kernel::object_manager->get_object_from_handle<mutant_object_t>(signal_handle);

	if (signal_mutant && signal_mutant->owned)
	{
		signal_mutant->count--;
		if (signal_mutant->count <= 0)
		{
			signal_mutant->owned = false;
			signal_mutant->owner_thread_id = 0;
			signal_mutant->count = 0;
		}
	}

	const auto wait_event = kernel::object_manager->get_object_from_handle<event_object_t>(wait_handle);

	if (wait_event && wait_event->signaled && wait_event->event_type == event_object_t::synchronization)
	{
		wait_event->signaled = false;
	}

	write_nt_success(emulator);
}

void redirect_ntoskrnl_sync_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_create_event>(emulator, mapped_image, "NtCreateEvent");
	redirect_handler<handle_create_event>(emulator, mapped_image, "ZwCreateEvent");

	redirect_handler<handle_set_event>(emulator, mapped_image, "NtSetEvent");
	redirect_handler<handle_set_event>(emulator, mapped_image, "ZwSetEvent");

	redirect_handler<handle_clear_event>(emulator, mapped_image, "NtClearEvent");
	redirect_handler<handle_clear_event>(emulator, mapped_image, "ZwClearEvent");

	redirect_handler<handle_reset_event>(emulator, mapped_image, "NtResetEvent");
	redirect_handler<handle_reset_event>(emulator, mapped_image, "ZwResetEvent");

	redirect_handler<handle_query_event>(emulator, mapped_image, "NtQueryEvent");
	redirect_handler<handle_query_event>(emulator, mapped_image, "ZwQueryEvent");

	redirect_handler<handle_create_mutant>(emulator, mapped_image, "NtCreateMutant");
	redirect_handler<handle_create_mutant>(emulator, mapped_image, "ZwCreateMutant");

	redirect_handler<handle_release_mutant>(emulator, mapped_image, "NtReleaseMutant");
	redirect_handler<handle_release_mutant>(emulator, mapped_image, "ZwReleaseMutant");

	redirect_handler<handle_create_semaphore>(emulator, mapped_image, "NtCreateSemaphore");
	redirect_handler<handle_create_semaphore>(emulator, mapped_image, "ZwCreateSemaphore");

	redirect_handler<handle_release_semaphore>(emulator, mapped_image, "NtReleaseSemaphore");
	redirect_handler<handle_release_semaphore>(emulator, mapped_image, "ZwReleaseSemaphore");

	redirect_handler<handle_create_keyed_event>(emulator, mapped_image, "NtCreateKeyedEvent");
	redirect_handler<handle_create_keyed_event>(emulator, mapped_image, "ZwCreateKeyedEvent");

	redirect_handler<handle_wait_for_keyed_event>(emulator, mapped_image, "NtWaitForKeyedEvent");
	redirect_handler<handle_wait_for_keyed_event>(emulator, mapped_image, "ZwWaitForKeyedEvent");

	redirect_handler<handle_release_keyed_event>(emulator, mapped_image, "NtReleaseKeyedEvent");
	redirect_handler<handle_release_keyed_event>(emulator, mapped_image, "ZwReleaseKeyedEvent");

	redirect_handler<handle_wait_for_single_object>(emulator, mapped_image, "NtWaitForSingleObject");
	redirect_handler<handle_wait_for_single_object>(emulator, mapped_image, "ZwWaitForSingleObject");

	redirect_handler<handle_wait_for_multiple_objects>(emulator, mapped_image, "NtWaitForMultipleObjects");
	redirect_handler<handle_wait_for_multiple_objects>(emulator, mapped_image, "ZwWaitForMultipleObjects");

	redirect_handler<handle_signal_and_wait>(emulator, mapped_image, "NtSignalAndWaitForSingleObject");
	redirect_handler<handle_signal_and_wait>(emulator, mapped_image, "ZwSignalAndWaitForSingleObject");
}
