#pragma once
// Selects the Unicorn backend for the guest architecture.
//
// Both backends derive from unicorn_emu_base and differ only in register
// translation and the uc_open arguments. Include this rather than an
// emu/<arch>/unicorn.hpp directly: `unicorn_emu` then names the right one and
// brings its own arch, so nothing outside this header has to pair the two up.

#include "../target.hpp"

#if defined(KERNEMUL_ARCH_ARM64)
	#include "arm64/unicorn.hpp"

	using unicorn_vcpu = arm64_unicorn_vcpu;
	using unicorn_emu  = arm64_unicorn_emu;
#else
	#include "x86/unicorn.hpp"

	using unicorn_vcpu = x86_unicorn_vcpu;
	using unicorn_emu  = x86_unicorn_emu;
#endif
