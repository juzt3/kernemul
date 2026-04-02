#pragma once
#include "../image/mapped_image.hpp"
#include "../kernel/kernel.hpp"
#include "../kernel/kernel_string.hpp"
#include "../util/util.hpp"
#include "../util/logs.hpp"

#include <ia32-doc/ia32.hpp>
#include <functional>
#include <random>
#include <string>
#include <string_view>

void redirect_function(const kernel::function_implementation_t& function_impl,
	const kernel_image_t& mapped_image, std::string_view name);

void redirect_function(const std::function<void()>& function_impl,
	const kernel_image_t& mapped_image, std::string_view name);

void write_return_value(const std::shared_ptr<emulator_t>& emulator, std::uint64_t value);
void write_nt_status(const std::shared_ptr<emulator_t>& emulator, std::uint32_t code);
void write_nt_success(const std::shared_ptr<emulator_t>& emulator);

std::uint64_t read_guest_vararg(const emulator_t& emulator, emulator_t::address_type va_list_address,
	std::size_t& index);

void write_guest_wstring_buffer(emulator_t& emulator, emulator_t::address_type buffer_address,
	std::size_t buffer_count, std::wstring_view str);

std::wstring guest_vswprintf(const emulator_t& emulator, std::wstring_view format,
	emulator_t::address_type va_list_address);

std::string guest_vsprintf(const emulator_t& emulator, std::string_view format,
	emulator_t::address_type va_list_address);
