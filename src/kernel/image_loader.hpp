#pragma once

#include "../emulator/emulator.hpp"
#include "../emulator/object.hpp"
#include "../image/mapped_image.hpp"
#include "kernel_def.hpp"

#include <memory>
#include <string_view>

std::shared_ptr<mapped_image_t> map_kernel_image(const std::shared_ptr<emulator_t>& emulator,
	std::string_view name, bool fix_imports = true,
	std::wstring_view directory = L"\\SystemRoot\\system32\\");

emulator_object_t<UNICODE_STRING> allocate_unicode_string_object(const std::shared_ptr<emulator_t>& emulator,
	std::wstring_view str, const std::string& object_name = {});
