#pragma once
#include "../emulator/emulator.hpp"
#include "../emulator/object.hpp"
#include "../image/mapped_image.hpp"
#include "../filesystem/filesystem.hpp"
#include "kernel_def.hpp"
#include "process_loader.hpp"
#include "thread.hpp"

#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>
#include <queue>

namespace kernel
{
	using function_implementation_t = std::function<void(bool& skip_return)>;

	inline emulator_object_t<_LIST_ENTRY> ps_loaded_module_list;
	inline std::vector<std::shared_ptr<kernel_image_t>> module_entries;
	inline std::shared_ptr<kernel_image_t> emulated_module;

	inline std::vector<std::shared_ptr<process_t>> process_entries;

	inline std::queue<std::shared_ptr<thread_t>> pending_threads;
	inline std::shared_ptr<thread_t> current_thread;

	inline std::shared_ptr<filesystem_t> filesystem;
	inline std::unordered_map<emulator_t::address_type, function_implementation_t> redirected_functions;

	[[nodiscard]] std::shared_ptr<kernel_image_t> find_module(std::string_view name);
	[[nodiscard]] std::shared_ptr<kernel_image_t> find_module_from_rip(emulator_t::address_type rip);
	[[nodiscard]] std::optional<function_implementation_t> find_redirected_function(emulator_t::address_type address);
}
