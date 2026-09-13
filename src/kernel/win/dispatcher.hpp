#pragma once
#include "types.hpp"
#include "../../emu/object.hpp"
#include <chrono>
#include <cstdint>

namespace win
{

// KOBJECTS. The guest reads these back -- the verifier checks an object's
// header before touching anything else, and KeReadState* dispatch on it.
enum dispatcher_type : std::uint8_t
{
	event_notification_object    = 0,
	event_synchronization_object = 1,
	mutant_object                = 2,
	process_object               = 3,
	queue_object                 = 4,
	semaphore_object             = 5,
	thread_object                = 6,
	gate_object                  = 7,
	timer_notification_object    = 8,
	timer_synchronization_object = 9,
};

// ntoskrnl's own initialisers write Size in ULONGs rather than bytes.
template <typename T>
constexpr std::uint8_t dispatcher_size()
{
	return static_cast<std::uint8_t>(sizeof(T) / sizeof(std::uint32_t));
}

template <typename T>
[[nodiscard]] std::int32_t signal_state(const emu_object<T>& obj)
{
	return static_cast<std::int32_t>(
		obj.template field(&T::Header).field(&_DISPATCHER_HEADER::SignalState).read());
}

template <typename T>
void set_signal_state(const emu_object<T>& obj, const std::int32_t state)
{
	obj.template field(&T::Header).field(&_DISPATCHER_HEADER::SignalState).write(state);
}

// A wait list is circular and anchored in the object itself, so an empty one
// points at its own head -- a guest walking it has to find it terminated even
// though nothing here ever queues a waiter.
template <typename T>
void init_dispatcher(const emu_object<T>& obj, const dispatcher_type type,
	const std::int32_t state)
{
	auto header = obj.template field(&T::Header);

	header.field(&_DISPATCHER_HEADER::Type).write(type);
	header.field(&_DISPATCHER_HEADER::Signalling).write(0);
	header.field(&_DISPATCHER_HEADER::Size).write(dispatcher_size<T>());
	header.field(&_DISPATCHER_HEADER::SignalState).write(state);

	const auto head = header.address() + offsetof(_DISPATCHER_HEADER, WaitListHead);
	header.field(&_DISPATCHER_HEADER::WaitListHead).write(guest_links(head, head));
}


// A dispatcher object reached by address rather than by type. The header sits
// at the front of every one of them, so the type and the signal state are
// readable without knowing which kind it is -- which is what a wait is handed.
[[nodiscard]] inline emu_object<_DISPATCHER_HEADER> header_at(addr_space& space,
	const addr_t object)
{
	return emu_object<_DISPATCHER_HEADER>(space, object);
}

[[nodiscard]] inline dispatcher_type type_at(addr_space& space, const addr_t object)
{
	return static_cast<dispatcher_type>(
		header_at(space, object).field(&_DISPATCHER_HEADER::Type).read());
}

[[nodiscard]] inline std::int32_t state_at(addr_space& space, const addr_t object)
{
	return header_at(space, object).field(&_DISPATCHER_HEADER::SignalState).read();
}

inline void set_state_at(addr_space& space, const addr_t object, const std::int32_t state)
{
	header_at(space, object).field(&_DISPATCHER_HEADER::SignalState).write(state);
}

// Waiting on a dispatcher object.
//
// Nothing here keeps a wait queue: a thread that cannot proceed gives up its
// cpu and is entered again at the same call, so a wait is a re-check paced by
// the scheduler rather than a wake-up from whoever signalled. A guest cannot
// tell the two apart except in latency -- it blocks, and stops blocking once
// the object is signalled -- but a driver timing its own wakeup sees the
// interval below rather than nothing.
inline constexpr auto wait_poll_interval = std::chrono::milliseconds(1);

// Whether the object is signalled at all, without taking it: what a wait on
// several objects asks before it takes any of them.
[[nodiscard]] inline bool is_signalled(addr_space& space, const addr_t object,
	const addr_t waiter)
{
	const auto state = state_at(space, object);

	// A mutant its own owner is waiting on is always available to it, which is
	// what makes it recursive.
	if (state <= 0 && type_at(space, object) == mutant_object)
		return waiter && guest_va(emu_object<_KMUTANT>(space, object)
			.field(&_KMUTANT::OwnerThread).read()) == waiter;

	return state > 0;
}

// Taking the object, which is what the type decides: a notification event stays
// signalled for everyone, a synchronization event and a semaphore are consumed
// by whoever takes them, and a mutant records who holds it and how deep.
inline void take(addr_space& space, const addr_t object, const addr_t waiter)
{
	const auto type = type_at(space, object);
	const auto state = state_at(space, object);

	switch (type)
	{
	case event_notification_object:
	case process_object:
	case thread_object:
	case timer_notification_object:
		// Stays signalled: everything waiting on one of these is released, and
		// it is signalled again only by whoever set it.
		break;

	case mutant_object:
		set_state_at(space, object, state - 1);
		emu_object<_KMUTANT>(space, object).field(&_KMUTANT::OwnerThread)
			.write(guest_ptr<_KTHREAD>(waiter));
		break;

	case semaphore_object:
		set_state_at(space, object, state - 1);
		break;

	default:
		// A synchronization event, a gate, a queue: one waiter takes it and it
		// goes back to unsignalled behind them.
		set_state_at(space, object, 0);
		break;
	}
}

}
