#pragma once

#include "../../emulator/emulator.hpp"
#include "../../image/mapped_image.hpp"

void initialize_ntoskrnl_debugger_state(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image);
