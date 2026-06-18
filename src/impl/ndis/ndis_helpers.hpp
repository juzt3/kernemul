#pragma once
#include "../impl.hpp"

void redirect_ndis_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);
