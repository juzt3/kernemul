#pragma once
#include "../addr_space.hpp"
#include <unordered_map>

namespace x86
{
	union virt_addr
	{
		std::uint64_t val;
		struct
		{
			std::uint64_t offset : 12;
			std::uint64_t pt     : 9;
			std::uint64_t pd     : 9;
			std::uint64_t pdpt   : 9;
			std::uint64_t pml4   : 9;
			std::uint64_t reserved : 16;
		};
	};

	struct addr_space : ::addr_space
	{
		addr_t pml4_pa = 0;
		std::unordered_map<addr_t, addr_t> shadow;
	};
}
