#pragma once

#include "../../emulator/object.hpp"
#include "../../image/mapped_image.hpp"
#include "../../kernel_def.hpp"

#include <portable_executable/image.hpp>
#include <ia32-doc/ia32.hpp>
#include <spdlog/spdlog.h>

#include <functional>
#include <string>
#include <unordered_map>

using function_implementation_t = std::function<void()>;

void redirect_image_export(const function_implementation_t& function_impl,
	const portable_executable::image_t* pe_image,
	const mapped_image_t& mapped_image, std::string_view name);

void write_return_value(const std::shared_ptr<emulator_t>& emulator, std::uint64_t value);
void write_nt_status(const std::shared_ptr<emulator_t>& emulator, std::uint32_t code);
void write_nt_success(const std::shared_ptr<emulator_t>& emulator);
void write_dummy_handle(const std::shared_ptr<emulator_t>& emulator, emulator_t::address_type handle_address);

template <class T>
std::basic_string<T> read_guest_basic_string(const emulator_t& emulator, emulator_t::address_type address)
{
	std::basic_string<T> result;

	std::int64_t count = -1;
	T character = 1;

	do
	{
		++count;

		const emulator_err_t error = emulator.read_virtual_memory(
			address + count * sizeof(T), &character, sizeof(character));

		error.throw_if("read memory");

		if (character)
		{
			result += character;
		}
	} while (character);

	return result;
}

inline std::wstring read_guest_wstring(const emulator_t& emulator, const emulator_t::address_type address)
{
	return read_guest_basic_string<wchar_t>(emulator, address);
}

inline std::string read_guest_string(const emulator_t& emulator, const emulator_t::address_type address)
{
	return read_guest_basic_string<char>(emulator, address);
}

inline std::string narrow_wstring(const std::wstring_view wide)
{
	std::string result;
	result.reserve(wide.size());

	for (const auto wc : wide)
	{
		result += static_cast<char>(wc & 0xFF);
	}

	return result;
}

std::uint64_t read_guest_vararg(const emulator_t& emulator, emulator_t::address_type va_list_address,
	std::size_t& index);

void write_guest_wstring_buffer(emulator_t& emulator, emulator_t::address_type buffer_address,
	std::size_t buffer_count, std::wstring_view str);

std::wstring guest_vswprintf(const emulator_t& emulator, std::wstring_view format,
	emulator_t::address_type va_list_address);

std::string guest_vsprintf(const emulator_t& emulator, std::string_view format,
	emulator_t::address_type va_list_address);

void redirect_ntoskrnl_string_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image, const portable_executable::image_t* pe_image);

void redirect_ntoskrnl_memory_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image, const portable_executable::image_t* pe_image);

void redirect_ntoskrnl_time_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image, const portable_executable::image_t* pe_image);

void redirect_ntoskrnl_registry_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image, const portable_executable::image_t* pe_image);

void redirect_ntoskrnl_format_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image, const portable_executable::image_t* pe_image);

void redirect_ntoskrnl_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image, const portable_executable::image_t* pe_image);

class filesystem_t;

void redirect_ntoskrnl_file_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image, const portable_executable::image_t* pe_image,
	const std::shared_ptr<filesystem_t>& filesystem);
