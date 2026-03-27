#pragma once
#include "../../image/mapped_image.hpp"
#include "../../kernel/kernel.hpp"
#include "../../kernel/kernel_string.hpp"
#include "../../util/util.hpp"

#include <ia32-doc/ia32.hpp>
#include "../../util/logs.hpp"
#include <random>
#include <string>

void redirect_function(const kernel::function_implementation_t& function_impl,
	const kernel_image_t& mapped_image, std::string_view name);

void redirect_function(const std::function<void()>& function_impl,
	const kernel_image_t& mapped_image, std::string_view name);

void write_return_value(const std::shared_ptr<emulator_t>& emulator, std::uint64_t value);
void write_nt_status(const std::shared_ptr<emulator_t>& emulator, std::uint32_t code);
void write_nt_success(const std::shared_ptr<emulator_t>& emulator);
void write_dummy_handle(const std::shared_ptr<emulator_t>& emulator, emulator_t::address_type handle_address);

std::uint64_t read_guest_vararg(const emulator_t& emulator, emulator_t::address_type va_list_address,
	std::size_t& index);

void write_guest_wstring_buffer(emulator_t& emulator, emulator_t::address_type buffer_address,
	std::size_t buffer_count, std::wstring_view str);

std::wstring guest_vswprintf(const emulator_t& emulator, std::wstring_view format,
	emulator_t::address_type va_list_address);

std::string guest_vsprintf(const emulator_t& emulator, std::string_view format,
	emulator_t::address_type va_list_address);

void redirect_ntoskrnl_string_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image);

void redirect_ntoskrnl_memory_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image);

void redirect_ntoskrnl_time_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image);

void redirect_ntoskrnl_registry_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image);

void redirect_ntoskrnl_format_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image);

void redirect_ntoskrnl_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image);

void redirect_ntoskrnl_sysinfo_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image);

void redirect_ntoskrnl_object_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image);

template <typename T>
T generate_random(T min_value, T max_value)
{
	static std::mt19937_64 engine(std::random_device{}());

	std::uniform_int_distribution<T> distribution(min_value, max_value);

	return distribution(engine);
}

class filesystem_t;

void redirect_ntoskrnl_file_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image,
	const std::shared_ptr<filesystem_t>& filesystem);
