#pragma once
#include "types.hpp"
#include "../../emu/object.hpp"
#include <cstdint>

namespace win
{

// Bit 0 says the object has started running down, so a reference moves the value by two.
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

[[nodiscard]] inline bool acquire_rundown(const rundown_ref& run_ref)
{
	const auto value = rundown_count(run_ref).read();

	if (value & rundown_active)
		return false;

	rundown_count(run_ref).write(value + rundown_reference);

	return true;
}

[[nodiscard]] inline bool release_rundown(const rundown_ref& run_ref)
{
	const auto value = rundown_count(run_ref).read();
	const auto references = value & ~rundown_active;

	if (references < rundown_reference)
		return false;

	rundown_count(run_ref).write((value & rundown_active) | (references - rundown_reference));

	return true;
}

// Waiting for the outstanding references is the caller's problem.
inline void begin_rundown(const rundown_ref& run_ref)
{
	rundown_count(run_ref).write(rundown_active);
}

}
