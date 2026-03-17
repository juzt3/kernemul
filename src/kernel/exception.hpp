#pragma once
#include "../emulator/emulator.hpp"

namespace kernel
{
	void handle_exception(const std::shared_ptr<emulator_t>& emulator, emulator_t::address_type rip,
		std::uint32_t code, emulator_t::address_type faulting_address);
}
