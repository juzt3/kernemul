#pragma once
#include <string_view>

// Pick with the KERNEMUL_ARCH cmake option ("x64" or "arm64").

#if !defined(KERNEMUL_ARCH_ARM64) && !defined(KERNEMUL_ARCH_X64)
	#define KERNEMUL_ARCH_X64 1
#endif

#if defined(KERNEMUL_ARCH_ARM64) && defined(KERNEMUL_ARCH_X64)
	#error "define exactly one of KERNEMUL_ARCH_X64 / KERNEMUL_ARCH_ARM64"
#endif

namespace target
{
#if defined(KERNEMUL_ARCH_ARM64)
	inline constexpr std::string_view name = "arm64";

	// Each arch needs its own ntoskrnl.exe, so each gets its own guest root.
	inline constexpr std::string_view guest_fs_dir = "fs_arm64/";
#else
	inline constexpr std::string_view name = "x64";

	inline constexpr std::string_view guest_fs_dir = "fs_x86_64/";
#endif
}
