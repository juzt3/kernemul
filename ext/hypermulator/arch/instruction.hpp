#pragma once
#include <cstdint>

namespace hm
{
	static constexpr std::uint64_t max_instruction_length = 15;

	enum machine_mode_t : std::uint8_t
	{
		machine_mode_16,
		machine_mode_32,
		machine_mode_64
	};
}
