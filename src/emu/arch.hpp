#pragma once
#include "defs.hpp"
#include <cstddef>

using reg_t = int;

struct arch
{
	virtual ~arch() = default;
	virtual reg_t pc() const = 0;
};

#include "x86/arch.hpp"
