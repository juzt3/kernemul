#pragma once
#include "defs.hpp"
#include <cstddef>

struct arch
{
	virtual ~arch() = default;
};

struct x86_arch : arch
{
	
};
