#pragma once

#include "../emulator/emulator.hpp"
#include "../emulator/object.hpp"
#include "../image/mapped_image.hpp"
#include "kernel_def.hpp"

#include <memory>
#include <string_view>

namespace kernel
{
	std::shared_ptr<mapped_image_t> map_kernel_image(const std::shared_ptr<emulator_t>& emulator, std::string_view name,
	                                                 bool fix_imports = true,
	                                                 std::wstring_view directory = L"\\SystemRoot\\system32\\");
}
