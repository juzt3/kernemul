#pragma once
#include "types.hpp"
#include "../../emu/object.hpp"
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

}
