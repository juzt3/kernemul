#pragma once
#include "types.hpp"
#include "../../emu/object.hpp"
#include <cstdint>

// Bitfields in anonymous unions that emu_object cannot name, at the positions the header documents.

namespace win
{

enum eprocess_flag : std::uint32_t
{
	process_exiting = 1u << 2,
};

enum eprocess_flag3 : std::uint32_t
{
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

// PS_PROTECTION::Level is the type in its low three bits with the signer above it.
[[nodiscard]] inline PS_PROTECTED_TYPE protection_type(const emu_object<_EPROCESS>& process)
{
	constexpr std::uint8_t protection_type_bits = 0x7;

	return static_cast<PS_PROTECTED_TYPE>(
		process.field(&_EPROCESS::Protection).field(&_PS_PROTECTION::Level).read()
			& protection_type_bits);
}

}
