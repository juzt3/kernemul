#pragma once

#include "../emulator/emulator.hpp"

#include <cstdint>
#include <memory>

namespace user
{
	inline emulator_t::address_type ki_user_exception_dispatcher_address = 0;

	void dispatch_access_violation(const std::shared_ptr<emulator_t>& emulator,
		emulator_t::address_type fault_address, bool is_write);

	void dispatch_exception(const std::shared_ptr<emulator_t>& emulator,
		std::uint32_t exception_code,
		emulator_t::address_type exception_address,
		const std::uint64_t* parameters, std::uint32_t parameter_count);

	void clear_exception_dispatch_guard();
}
