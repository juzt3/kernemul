#pragma once
#include "../impl.hpp"

void redirect_ntoskrnl_string_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);

void redirect_ntoskrnl_memory_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);

void redirect_ntoskrnl_time_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);

void redirect_ntoskrnl_registry_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);

void redirect_ntoskrnl_format_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);

void redirect_ntoskrnl_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);

void redirect_ntoskrnl_sysinfo_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);

void redirect_ntoskrnl_object_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);

void redirect_ntoskrnl_file_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image);
