#include "nt_dispatch_ops.hpp"
#include "../win_kernel.hpp"
#include "../dispatcher.hpp"
#include "../objects.hpp"
#include "../thread.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <string_view>

namespace
{

// EVENT_TYPE, which is the dispatcher type under a different name.
constexpr std::uint32_t notification_event = 0;

// EVENT_INFORMATION_CLASS.
constexpr std::uint32_t event_basic_information = 0;

#pragma pack(push, 4)
struct event_basic_information_t
{
	std::uint32_t event_type;
	std::int32_t  event_state;
};
#pragma pack(pop)

// The object body is the dispatcher object itself, so a driver handed the
// pointer behind the handle can pass it to Ke* as-is.
template <typename T>
std::uint64_t create_dispatcher(win_kernel_state& state, const win::dispatcher_type type,
	const std::int32_t signal_state, const std::uint32_t access, std::string name)
{
	const T zeroed{};
	const auto addr = state.objs.create_object(0, &zeroed, sizeof(T),
		std::make_shared<dispatcher_host>(type, std::move(name)), prot_rw | prot_supervisor);

	if (!addr)
		return 0;

	emu_object<T> obj(*state.emulator()->emu().default_addr_space(), addr);
	win::init_dispatcher(obj, type, signal_state);

	return state.sys_proc->handle_table().create_handle(addr, access);
}

// The dispatcher object a handle names, and the type it turned out to be: a
// caller passing an event handle to NtReleaseMutant gets told, rather than
// having the wrong fields written over it.
struct resolved
{
	addr_t address = 0;
	std::shared_ptr<dispatcher_host> host;
};

resolved resolve(win_kernel_state& state, const std::uint64_t handle,
	const win::dispatcher_type expected, const std::string_view who)
{
	const auto entry = state.sys_proc->handle_table().lookup_handle(handle);

	if (!entry)
	{
		THREAD_LOG_WARN("{}: handle 0x{:X} is not open", who, handle);
		return {};
	}

	auto host = state.objs.get_object<dispatcher_host>(entry->body_addr);

	if (!host)
	{
		THREAD_LOG_WARN("{}: handle 0x{:X} is not a dispatcher object", who, handle);
		return {};
	}

	// An event has two types, and either answers to an event handle.
	const bool event_pair = (expected == win::event_notification_object
			|| expected == win::event_synchronization_object)
		&& (host->type == win::event_notification_object
			|| host->type == win::event_synchronization_object);

	if (host->type != expected && !event_pair)
	{
		THREAD_LOG_WARN("{}: handle 0x{:X} names a type {} object, not {}",
			who, handle, static_cast<int>(host->type), static_cast<int>(expected));
		return {};
	}

	return { entry->body_addr, std::move(host) };
}

std::string attribute_name(vcpu& cpu, const emu_object<_OBJECT_ATTRIBUTES>& object_attributes)
{
	auto& space = *cpu.curr_addr_space();

	const emu_object<_UNICODE_STRING> name(space, object_attributes
		? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
		: 0);

	return narrow_wstring(win::read_unicode_string(name));
}

}

// The dispatcher objects a driver makes by handle rather than by pointer. The
// body behind each handle is the real KEVENT, KSEMAPHORE or KMUTANT, so the
// Ke* handlers and these two see the same state.
//
// Waiting is what is missing: nothing here blocks on a dispatcher object, so
// the handlers that wait are left unregistered rather than returning as though
// the wait had been satisfied.
void modules::register_ntoskrnl_dispatch_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	auto create_event = [st](vcpu& cpu, emu_object<std::uint64_t> event_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const std::uint32_t event_type, const bool initial_state) -> NTSTATUS
	{
		if (!event_handle)
			return STATUS_INVALID_PARAMETER;

		const auto name = attribute_name(cpu, object_attributes);
		const auto type = event_type == notification_event
			? win::event_notification_object : win::event_synchronization_object;

		const auto handle = create_dispatcher<_KEVENT>(*st, type, initial_state ? 1 : 0,
			desired_access, name);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		event_handle.write(handle);

		THREAD_LOG_INFO("NtCreateEvent('{}', {}, state={}) -> handle=0x{:X}",
			name, event_type == notification_event ? "notification" : "synchronization",
			initial_state, handle);

		return STATUS_SUCCESS;
	};

	// Nothing puts an event in a namespace, so there is never one to open by
	// name -- which is the answer the real one gives for a name that is absent.
	state.redirect_ntzw(mod, "OpenEvent",
		[](vcpu& cpu, emu_object<std::uint64_t> event_handle, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			if (event_handle)
				event_handle.write(0);

			THREAD_LOG_WARN("NtOpenEvent('{}', access=0x{:X}): nothing here names an event",
				attribute_name(cpu, object_attributes), desired_access);

			return STATUS_OBJECT_NAME_NOT_FOUND;
		});

	auto set_event = [st](vcpu& cpu, const std::uint64_t event_handle,
		emu_object<std::int32_t> previous_state) -> NTSTATUS
	{
		const auto found = resolve(*st, event_handle, win::event_notification_object, "NtSetEvent");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		emu_object<_KEVENT> event(*cpu.curr_addr_space(), found.address);
		const auto previous = win::signal_state(event);
		win::set_signal_state(event, 1);

		if (previous_state)
			previous_state.write(previous);

		THREAD_LOG_INFO("NtSetEvent(0x{:X}, '{}') -> was {}",
			event_handle, found.host->name, previous);

		return STATUS_SUCCESS;
	};

	// NtResetEvent reports the state it found; NtClearEvent does the same work
	// and says nothing, which is the only difference between them.
	auto reset_event = [st](vcpu& cpu, const std::uint64_t event_handle,
		emu_object<std::int32_t> previous_state) -> NTSTATUS
	{
		const auto found = resolve(*st, event_handle, win::event_notification_object,
			"NtResetEvent");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		emu_object<_KEVENT> event(*cpu.curr_addr_space(), found.address);
		const auto previous = win::signal_state(event);
		win::set_signal_state(event, 0);

		if (previous_state)
			previous_state.write(previous);

		THREAD_LOG_INFO("NtResetEvent(0x{:X}, '{}') -> was {}",
			event_handle, found.host->name, previous);

		return STATUS_SUCCESS;
	};

	auto clear_event = [st](vcpu& cpu, const std::uint64_t event_handle) -> NTSTATUS
	{
		const auto found = resolve(*st, event_handle, win::event_notification_object,
			"NtClearEvent");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		emu_object<_KEVENT> event(*cpu.curr_addr_space(), found.address);
		win::set_signal_state(event, 0);

		THREAD_LOG_INFO("NtClearEvent(0x{:X}, '{}')", event_handle, found.host->name);

		return STATUS_SUCCESS;
	};

	auto query_event = [st](vcpu& cpu, const std::uint64_t event_handle,
		const std::uint32_t event_information_class, const addr_t event_information,
		const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
	{
		const auto found = resolve(*st, event_handle, win::event_notification_object,
			"NtQueryEvent");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		if (event_information_class != event_basic_information)
		{
			THREAD_LOG_WARN("NtQueryEvent: unhandled class {}", event_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}

		if (return_length)
			return_length.write(sizeof(event_basic_information_t));

		if (length < sizeof(event_basic_information_t))
			return STATUS_INFO_LENGTH_MISMATCH;

		auto& space = *cpu.curr_addr_space();
		const emu_object<_KEVENT> event(space, found.address);

		event_basic_information_t info{};
		info.event_type = found.host->type == win::event_notification_object ? 0 : 1;
		info.event_state = win::signal_state(event);

		emu_object<event_basic_information_t>(space, event_information).write(info);

		THREAD_LOG_INFO("NtQueryEvent(0x{:X}, '{}') -> type={}, state={}",
			event_handle, found.host->name, info.event_type, info.event_state);

		return STATUS_SUCCESS;
	};

	auto create_semaphore = [st](vcpu& cpu, emu_object<std::uint64_t> semaphore_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const std::int32_t initial_count, const std::int32_t maximum_count) -> NTSTATUS
	{
		if (!semaphore_handle)
			return STATUS_INVALID_PARAMETER;

		if (maximum_count <= 0 || initial_count < 0 || initial_count > maximum_count)
			return STATUS_INVALID_PARAMETER;

		const auto name = attribute_name(cpu, object_attributes);
		const auto handle = create_dispatcher<_KSEMAPHORE>(*st, win::semaphore_object,
			initial_count, desired_access, name);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		// The limit lives past the dispatcher header, and KeReleaseSemaphore
		// checks against it.
		const auto entry = st->sys_proc->handle_table().lookup_handle(handle);
		emu_object<_KSEMAPHORE>(*cpu.curr_addr_space(), entry->body_addr)
			.field(&_KSEMAPHORE::Limit).write(maximum_count);

		semaphore_handle.write(handle);

		THREAD_LOG_INFO("NtCreateSemaphore('{}', initial={}, maximum={}) -> handle=0x{:X}",
			name, initial_count, maximum_count, handle);

		return STATUS_SUCCESS;
	};

	auto release_semaphore = [st](vcpu& cpu, const std::uint64_t semaphore_handle,
		const std::int32_t release_count, emu_object<std::int32_t> previous_count) -> NTSTATUS
	{
		const auto found = resolve(*st, semaphore_handle, win::semaphore_object,
			"NtReleaseSemaphore");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		if (release_count <= 0)
			return STATUS_INVALID_PARAMETER;

		emu_object<_KSEMAPHORE> semaphore(*cpu.curr_addr_space(), found.address);

		const auto previous = win::signal_state(semaphore);
		const auto limit = semaphore.field(&_KSEMAPHORE::Limit).read();

		if (previous + release_count > limit)
		{
			THREAD_LOG_WARN("NtReleaseSemaphore(0x{:X}, '{}'): {} + {} is past the limit of {}",
				semaphore_handle, found.host->name, previous, release_count, limit);

			return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
		}

		win::set_signal_state(semaphore, previous + release_count);

		if (previous_count)
			previous_count.write(previous);

		THREAD_LOG_INFO("NtReleaseSemaphore(0x{:X}, '{}', release={}) -> was {}",
			semaphore_handle, found.host->name, release_count, previous);

		return STATUS_SUCCESS;
	};

	// A mutant is signalled when nobody holds it, so an unowned one starts at
	// one and an owned one at zero.
	auto create_mutant = [st](vcpu& cpu, emu_object<std::uint64_t> mutant_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		const bool initial_owner) -> NTSTATUS
	{
		if (!mutant_handle)
			return STATUS_INVALID_PARAMETER;

		const auto name = attribute_name(cpu, object_attributes);
		const auto handle = create_dispatcher<_KMUTANT>(*st, win::mutant_object,
			initial_owner ? 0 : 1, desired_access, name);

		if (!handle)
			return STATUS_INSUFFICIENT_RESOURCES;

		if (initial_owner)
		{
			const auto entry = st->sys_proc->handle_table().lookup_handle(handle);
			const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());
			const auto ethread = t ? t->ethread().address() : 0;

			emu_object<_KMUTANT>(*cpu.curr_addr_space(), entry->body_addr)
				.field(&_KMUTANT::OwnerThread)
				.write(guest_ptr<_KTHREAD>(ethread));
		}

		mutant_handle.write(handle);

		THREAD_LOG_INFO("NtCreateMutant('{}', initial_owner={}) -> handle=0x{:X}",
			name, initial_owner, handle);

		return STATUS_SUCCESS;
	};

	auto release_mutant = [st](vcpu& cpu, const std::uint64_t mutant_handle,
		emu_object<std::int32_t> previous_count) -> NTSTATUS
	{
		const auto found = resolve(*st, mutant_handle, win::mutant_object, "NtReleaseMutant");

		if (!found.address)
			return STATUS_INVALID_HANDLE;

		emu_object<_KMUTANT> mutant(*cpu.curr_addr_space(), found.address);
		const auto previous = win::signal_state(mutant);

		if (previous > 0)
		{
			THREAD_LOG_WARN("NtReleaseMutant(0x{:X}, '{}'): nobody holds it",
				mutant_handle, found.host->name);

			return STATUS_MUTANT_NOT_OWNED;
		}

		win::set_signal_state(mutant, previous + 1);
		mutant.field(&_KMUTANT::OwnerThread).write(nullptr);

		if (previous_count)
			previous_count.write(previous);

		THREAD_LOG_INFO("NtReleaseMutant(0x{:X}, '{}') -> was {}",
			mutant_handle, found.host->name, previous);

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "CreateEvent", create_event);
	state.redirect_ntzw(mod, "SetEvent", set_event);
	state.redirect_ntzw(mod, "ResetEvent", reset_event);
	state.redirect_ntzw(mod, "ClearEvent", clear_event);
	state.redirect_ntzw(mod, "QueryEvent", query_event);
	state.redirect_ntzw(mod, "CreateSemaphore", create_semaphore);
	state.redirect_ntzw(mod, "ReleaseSemaphore", release_semaphore);
	state.redirect_ntzw(mod, "CreateMutant", create_mutant);
	state.redirect_ntzw(mod, "ReleaseMutant", release_mutant);
}
