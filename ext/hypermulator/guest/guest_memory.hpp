#pragma once
#include <cstdint>

namespace hm
{
	enum class memory_copy_direction_t : std::uint8_t
	{
		read,
		write
	};

	enum protection_t : std::uint8_t
	{
		prot_none = 0,
		prot_read = 1,
		prot_write = 2,
		prot_read_write = 3,
		prot_execute = 4,
		prot_read_execute = 5,
		prot_write_execute = 6,
		prot_all = 7
	};

	struct mapped_memory_t
	{
		void* host_buffer;
		protection_t protection;
	};
}
