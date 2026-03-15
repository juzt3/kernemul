#include "kernel_string.hpp"

#include <spdlog/spdlog.h>

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

template <class T>
emulator_t::address_type allocate_basic_string(emulator_t& emulator, const std::basic_string_view<T> str,
	const bool terminate)
{
	if (str.empty())
	{
		throw std::runtime_error("unable to allocate empty string");
	}

	const std::span<const std::uint8_t> buffer = {
		reinterpret_cast<const std::uint8_t*>(str.data()),
		str.size() * sizeof(T)
	};

	const std::size_t buffer_size = buffer.size() + (terminate ? sizeof(T) : 0);

	const auto allocation = emulator.heap_allocate(buffer_size, prot_read_write);

	emulator_err_t error = allocation.error_or({});

	error.throw_if("string heap allocation");

	error = emulator.write_virtual_memory(*allocation, buffer);

	error.throw_if("write memory");

	if (terminate)
	{
		constexpr T terminator = { };

		error = emulator.write_virtual_memory(*allocation + buffer.size(), &terminator, sizeof(terminator));

		error.throw_if("write memory");
	}

	error = emulator.hook_memory(
		[&emulator](const emulator_t::address_type accessed_address, const protection_t access) -> bool
		{
			const auto rip = emulator.read_register<x86::reg::rip, emulator_t::address_type>();

			spdlog::info("instruction at 0x{:X} accessed allocated string (string address=0x{:X})", rip, accessed_address);

			return false;
		},
		prot_read_write,
		*allocation,
		*allocation + buffer_size
	).error_or({});

	error.throw_if("object hook attach");

	return *allocation;
}

std::wstring kernel::read_guest_wstring(const emulator_t& emulator, const emulator_t::address_type address)
{
	return read_guest_basic_string<wchar_t>(emulator, address);
}

std::string kernel::read_guest_string(const emulator_t& emulator, const emulator_t::address_type address)
{
	return read_guest_basic_string<char>(emulator, address);
}

emulator_t::address_type kernel::allocate_string(emulator_t& emulator, const std::string_view str,
	const bool terminate)
{
	return allocate_basic_string(emulator, str, terminate);
}

emulator_t::address_type kernel::allocate_wstring(emulator_t& emulator, const std::wstring_view str,
	const bool terminate)
{
	return allocate_basic_string(emulator, str, terminate);
}

UNICODE_STRING kernel::init_unicode_string(emulator_t& emulator, const std::wstring_view str)
{
	const emulator_t::address_type buffer = allocate_wstring(emulator, str, true);

	const std::uint16_t length = static_cast<std::uint16_t>(str.size() * sizeof(wchar_t));
	const std::uint16_t max_length = length + sizeof(wchar_t);

	const UNICODE_STRING result = {
		.Length = length,
		.MaximumLength = max_length,
		.Buffer = reinterpret_cast<PWSTR>(buffer)
	};

	return result;
}

emulator_object_t<UNICODE_STRING> kernel::allocate_unicode_string_object(const std::shared_ptr<emulator_t>& emulator,
	const std::wstring_view str, const std::string& object_name)
{
	const UNICODE_STRING contents = init_unicode_string(*emulator, str);

	return emulator_object_t<UNICODE_STRING>::allocate(emulator, contents, object_name);
}
