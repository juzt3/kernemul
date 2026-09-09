#pragma once
#include "defs.hpp"
#include <cstddef>

struct addr_space
{
	virtual ~addr_space() = default;
	virtual addr_t alloc(std::size_t size, mem_prot prot) = 0;
};
