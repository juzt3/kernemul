#pragma once
#include "../impl.hpp"

void redirect_ntoskrnl_sync_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);
