#pragma once
// Selects the generated Windows type set for the guest architecture.
//
// Both headers are produced by tools/gen_types.py from the matching ntoskrnl
// PDB. They define the same tag names with different layouts, so exactly one
// may be included -- see src/target.hpp for why the choice is compile time.

#include "../../target.hpp"

#if defined(KERNEMUL_ARCH_ARM64)
	#include "types_arm64.hpp"
#else
	#include "types_x64.hpp"
#endif
