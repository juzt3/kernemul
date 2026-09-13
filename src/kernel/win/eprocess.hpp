#pragma once
#include "types.hpp"
#include "../../emu/object.hpp"
#include <cstdint>

// The guest-side half of a process, as the handlers that answer questions about
// one read it. Most of what a driver asks about lives in bitfields inside
// anonymous unions, which a guest-memory read cannot reach: emu_object can name
// _EPROCESS::Flags but not _EPROCESS::ProcessExiting. So the bits are named
// here, at the positions the generated header documents, and each word gets its
// own type -- a Flags3 bit tested against Flags would otherwise compile.

namespace win
{

enum eprocess_flag : std::uint32_t
{
	// _EPROCESS::Flags, bit 2.
	process_exiting = 1u << 2,
};

enum eprocess_flag3 : std::uint32_t
{
	// _EPROCESS::Flags3, bit 12.
	system_process = 1u << 12,
};

[[nodiscard]] inline bool has_flag(const emu_object<_EPROCESS>& process, const eprocess_flag flag)
{
	return (process.field(&_EPROCESS::Flags).read() & flag) != 0;
}

[[nodiscard]] inline bool has_flag(const emu_object<_EPROCESS>& process, const eprocess_flag3 flag)
{
	return (process.field(&_EPROCESS::Flags3).read() & flag) != 0;
}

// PS_PROTECTION::Level is the type in its low three bits with the signer above
// it, so the byte a driver reads is not the level it compares against.
[[nodiscard]] inline PS_PROTECTED_TYPE protection_type(const emu_object<_EPROCESS>& process)
{
	constexpr std::uint8_t protection_type_bits = 0x7;

	return static_cast<PS_PROTECTED_TYPE>(
		process.field(&_EPROCESS::Protection).field(&_PS_PROTECTION::Level).read()
			& protection_type_bits);
}

}
