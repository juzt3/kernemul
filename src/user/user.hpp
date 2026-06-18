#pragma once

#include "../emulator/emulator.hpp"
#include "../kernel/thread.hpp"

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

class image_t;

namespace user
{
	struct context_t
	{
		emulator_t::address_type teb_address;
		emulator_t::address_type peb_address;
		emulator_t::address_type stack_base;
		emulator_t::address_type stack_limit;
		emulator_t::address_type image_base;
		emulator_t::address_type ntdll_base;
		emulator_t::address_type process_parameters;
	};

	constexpr std::uint64_t console_handle = 0x0003;
	constexpr std::uint64_t stdout_handle = 0x0007;
	constexpr std::uint64_t stdin_handle = 0x000B;
	constexpr std::uint64_t stderr_handle = 0x000F;
	constexpr std::uint64_t nul_handle = 0x0013;

	inline bool is_console_handle(const std::uint64_t handle)
	{
		return handle == console_handle
			|| handle == stdout_handle
			|| handle == stdin_handle
			|| handle == stderr_handle
			|| handle == nul_handle;
	}

	inline emulator_t::address_type usermode_peb_address = 0;
	inline std::vector<std::shared_ptr<image_t>> module_entries;

	void initialize(const std::shared_ptr<emulator_t>& emulator,
		const std::shared_ptr<image_t>& nt_image,
		std::string_view usermode_module_name);

	context_t set_up_structures(const std::shared_ptr<emulator_t>& emulator,
		emulator_t::address_type image_base,
		emulator_t::address_type ntdll_base,
		emulator_t::size_type image_size,
		emulator_t::size_type ntdll_size,
		const std::vector<std::shared_ptr<image_t>>& extra_modules = {});

	std::shared_ptr<thread_t> create_initial_thread(const std::shared_ptr<emulator_t>& emulator,
		emulator_t::address_type entry_point,
		emulator_t::address_type ldr_initialize_thunk,
		emulator_t::address_type rtl_user_thread_start,
		const context_t& context);
}
