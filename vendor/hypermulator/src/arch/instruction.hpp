#pragma once
#include <cstdint>

namespace hm
{
	static constexpr std::uint64_t max_insn_len = 15;

	enum machine_mode : std::uint8_t
	{
		machine_mode_16,
		machine_mode_32,
		machine_mode_64
	};
}
