#pragma once
#include "linked_list.hpp"
#include "types.hpp"
#include <chrono>
#include <cstdint>

using loaded_module_list_t = win_linked_list<
	_KLDR_DATA_TABLE_ENTRY,
	offsetof(_KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks)
>;

using active_process_list_t = win_linked_list<
	_EPROCESS,
	offsetof(_EPROCESS, ActiveProcessLinks)
>;

// A thread appears on two lists, both anchored in its own process: the
// scheduler's, whose head is in the KPROCESS, and the executive's, whose head
// is in the EPROCESS wrapped around it. Both thread through the same ETHREAD,
// at different offsets.
using kprocess_thread_list_t = win_linked_list<
	_ETHREAD,
	offsetof(_ETHREAD, Tcb.ThreadListEntry)
>;

using eprocess_thread_list_t = win_linked_list<
	_ETHREAD,
	offsetof(_ETHREAD, ThreadListEntry)
>;

#pragma pack(push, 4)
struct _RTL_OSVERSIONINFOW
{
	std::uint32_t dwOSVersionInfoSize;
	std::uint32_t dwMajorVersion;
	std::uint32_t dwMinorVersion;
	std::uint32_t dwBuildNumber;
	std::uint32_t dwPlatformId;
	char16_t szCSDVersion[128];
};

struct _RTL_OSVERSIONINFOEXW
{
	std::uint32_t dwOSVersionInfoSize;
	std::uint32_t dwMajorVersion;
	std::uint32_t dwMinorVersion;
	std::uint32_t dwBuildNumber;
	std::uint32_t dwPlatformId;
	char16_t szCSDVersion[128];
	std::uint16_t wServicePackMajor;
	std::uint16_t wServicePackMinor;
	std::uint16_t wSuiteMask;
	std::uint8_t wProductType;
	std::uint8_t wReserved;
};
#pragma pack(pop)

// The guest's WCHAR is two bytes whatever the host compiler makes of its own,
// and these structs are the guest's.
static_assert(sizeof(char16_t) == 2, "guest WCHAR is 2 bytes");
static_assert(sizeof(_RTL_OSVERSIONINFOW) == 0x114);
static_assert(sizeof(_RTL_OSVERSIONINFOEXW) == 0x11C);

inline constexpr std::uint32_t ver_platform_win32_nt = 2;
inline constexpr std::uint8_t ver_nt_workstation = 1;

// Which halves of the register set a CONTEXT is being asked for, and which it
// came back with. Every CONTEXT_* is the architecture's own tag or'd with one
// bit per half, so a half is named only when both are there -- which is why
// there is no operator& to test against zero: that would read CONTEXT_CONTROL
// on its own as naming every other half as well, and on the way back in means
// writing registers out of a buffer the caller never filled.
struct context_flags
{
	std::uint32_t bits = 0;

	[[nodiscard]] constexpr bool has(const context_flags part) const
	{
		return (bits & part.bits) == part.bits;
	}

	// The tag with one more bit set, which is how every CONTEXT_* past the tag
	// itself is spelled.
	[[nodiscard]] constexpr context_flags with(const std::uint32_t bit) const
	{
		return { bits | bit };
	}

	constexpr context_flags& operator|=(const context_flags other)
	{
		bits |= other.bits;
		return *this;
	}

	[[nodiscard]] friend constexpr context_flags operator|(context_flags a,
		const context_flags b)
	{
		return a |= b;
	}
};

// Windows counts 100ns ticks from 1601-01-01 and the host clock counts seconds
// from 1970-01-01, so a guest timestamp is the host's plus the gap.
inline constexpr std::int64_t win_epoch_delta_100ns = 116444736000000000;

using win_ticks = std::chrono::duration<std::int64_t, std::ratio<1, 10000000>>;

inline std::int64_t win_system_time()
{
	const auto now = std::chrono::system_clock::now().time_since_epoch();
	return win_epoch_delta_100ns + std::chrono::duration_cast<win_ticks>(now).count();
}
