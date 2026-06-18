#pragma once

#include "../../emulator/emulator.hpp"
#include "../../image/mapped_image.hpp"

#include <memory>

void redirect_ntoskrnl_syscall_handler(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);
