#pragma once
#include "types.hpp"
#include "../../emu/object.hpp"
#include <cstdint>

namespace win
{

// EX_RUNDOWN_REF packs a state bit underneath a reference count: bit 0 says the
// object has started running down and will take no further references, so a
// reference moves the value by two rather than by one. Anything that holds an
// object open against teardown -- a process against its own exit, a handle
// table against the process -- goes through one of these.
enum rundown_state : std::uint64_t
{
	rundown_active    = 0x1,
	rundown_reference = 0x2,
};

using rundown_ref = emu_object<_EX_RUNDOWN_REF>;

[[nodiscard]] inline auto rundown_count(const rundown_ref& run_ref)
{
	return run_ref.field(&_EX_RUNDOWN_REF::Count);
}

[[nodiscard]] inline std::uint64_t rundown_references(const rundown_ref& run_ref)
{
	return (rundown_count(run_ref).read() & ~rundown_active) / rundown_reference;
}

// Takes a reference unless the object is already running down, which is the one
// thing a caller has to check.
[[nodiscard]] inline bool acquire_rundown(const rundown_ref& run_ref)
{
	const auto value = rundown_count(run_ref).read();

	if (value & rundown_active)
		return false;

	rundown_count(run_ref).write(value + rundown_reference);

	return true;
}

// False when there was no reference to give back, which is a caller bug rather
// than a state the object can reach on its own.
[[nodiscard]] inline bool release_rundown(const rundown_ref& run_ref)
{
	const auto value = rundown_count(run_ref).read();
	const auto references = value & ~rundown_active;

	if (references < rundown_reference)
		return false;

	rundown_count(run_ref).write((value & rundown_active) | (references - rundown_reference));

	return true;
}

// Close the reference off so nothing further can take one. Waiting for the
// outstanding references is the caller's problem: nothing can drop one while
// the cpu that would is stopped inside a handler.
inline void begin_rundown(const rundown_ref& run_ref)
{
	rundown_count(run_ref).write(rundown_active);
}

}
