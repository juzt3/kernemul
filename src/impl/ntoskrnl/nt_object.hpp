#pragma once

#include "../../emulator/emulator.hpp"
#include "../../image/mapped_image.hpp"

void initialize_ntoskrnl_object_types(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);

void redirect_ntoskrnl_object_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);
