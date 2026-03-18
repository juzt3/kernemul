#pragma once

#include "../../emulator/emulator.hpp"
#include "../../image/mapped_image.hpp"

void redirect_ntoskrnl_object_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image);
