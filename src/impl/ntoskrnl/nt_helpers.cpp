#include "nt_helpers.hpp"

void redirect_function(const kernel::function_implementation_t& function_impl,
	const kernel_image_t& mapped_image, const std::string_view name)
{
	const auto symbol_address = mapped_image.find_symbol(std::string(name));

	if (!symbol_address)
	{
		throw std::runtime_error(std::format("unable to find symbol '{}'", name));
	}

	kernel::redirected_functions[*symbol_address] = function_impl;
}

void redirect_function(const std::function<void()>& function_impl,
	const kernel_image_t& mapped_image, const std::string_view name)
{
	redirect_function(
		kernel::function_implementation_t([function_impl](bool&) { function_impl(); }),
		mapped_image, name);
}

void write_return_value(const std::shared_ptr<emulator_t>& emulator, const std::uint64_t value)
{
	emulator->write_register<x86::reg::rax>(value);
}

void write_nt_status(const std::shared_ptr<emulator_t>& emulator, const std::uint32_t code)
{
	write_return_value(emulator, code);
}

void write_nt_success(const std::shared_ptr<emulator_t>& emulator)
{
	write_nt_status(emulator, 0);
}

void write_dummy_handle(const std::shared_ptr<emulator_t>& emulator, const emulator_t::address_type handle_address)
{
	constexpr std::uint64_t handle_value = 0x1337;

	const emulator_err_t error = emulator->write_virtual_memory(handle_address, &handle_value, sizeof(handle_value));

	error.throw_if("write memory");
}

std::uint64_t read_guest_vararg(const emulator_t& emulator, const emulator_t::address_type va_list_address,
	std::size_t& index)
{
	const emulator_t::address_type arg_address = va_list_address + index * sizeof(std::uint64_t);

	std::uint64_t value = 0;

	const emulator_err_t error = emulator.read_virtual_memory(arg_address, &value, sizeof(value));

	error.throw_if("read vararg");

	++index;

	return value;
}

void write_guest_wstring_buffer(emulator_t& emulator, const emulator_t::address_type buffer_address,
	const std::size_t buffer_count, const std::wstring_view str)
{
	const std::size_t chars_to_write = std::min(str.size(), buffer_count - 1);

	if (chars_to_write > 0)
	{
		const emulator_err_t error = emulator.write_virtual_memory(
			buffer_address, str.data(), chars_to_write * sizeof(wchar_t));

		error.throw_if("write memory");
	}

	constexpr wchar_t terminator = L'\0';

	const emulator_err_t error = emulator.write_virtual_memory(
		buffer_address + chars_to_write * sizeof(wchar_t), &terminator, sizeof(terminator));

	error.throw_if("write memory");
}
