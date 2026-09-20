#pragma once
// Include this rather than emu/<arch>/unicorn.hpp: `unicorn_emu` names the right backend and arch.

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
