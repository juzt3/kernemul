#pragma once
// They define the same tag names with different layouts, so exactly one may be included.

#include "../../target.hpp"

#if defined(KERNEMUL_ARCH_ARM64)
	#include "types_arm64.hpp"
#else
	#include "types_x64.hpp"
#endif
