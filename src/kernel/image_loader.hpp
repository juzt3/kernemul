#pragma once

#include "../emulator/emulator.hpp"
#include "../emulator/object.hpp"
#include "../image/mapped_image.hpp"
#include "kernel_def.hpp"

#include <memory>
#include <string_view>

namespace kernel
{
	struct image_load_options_t
	{
		bool fix_imports = false;
		bool user_accessible = false;
		bool load_pdb = false;
		bool add_to_module_list = true;
		bool register_redirections = true;
		bool monitor_data = true;
		std::wstring_view directory = L"\\SystemRoot\\system32\\";
	};

	std::shared_ptr<image_t> map_image(const std::shared_ptr<emulator_t>& emulator,
	                                          std::string_view name,
	                                          const image_load_options_t& options);

	std::shared_ptr<image_t> map_kernel_image(const std::shared_ptr<emulator_t>& emulator,
	                                                 std::string_view name,
	                                                 bool fix_imports = true,
	                                                 std::wstring_view directory = L"\\SystemRoot\\system32\\");

	std::shared_ptr<image_t> map_user_image(const std::shared_ptr<emulator_t>& emulator,
	                                               std::string_view name,
	                                               bool fix_imports = false,
	                                               bool load_pdb = false);
}
