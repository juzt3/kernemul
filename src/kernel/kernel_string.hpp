#pragma once

#include "../emulator/emulator.hpp"
#include "../emulator/object.hpp"
#include "kernel_def.hpp"

#include <string>
#include <string_view>

namespace kernel
{
	std::wstring read_guest_wstring(const emulator_t& emulator, emulator_t::address_type address);

	std::string read_guest_string(const emulator_t& emulator, emulator_t::address_type address);

	emulator_t::address_type allocate_string(emulator_t& emulator, std::string_view str, bool terminate);
	emulator_t::address_type allocate_wstring(emulator_t& emulator, std::wstring_view str, bool terminate);

	using guest_allocator_t = emulator_t::address_type(*)(std::size_t);
	emulator_t::address_type allocate_wstring(emulator_t& emulator, std::wstring_view str, guest_allocator_t allocator);

	UNICODE_STRING init_unicode_string(emulator_t& emulator, std::wstring_view str);

	emulator_object_t<UNICODE_STRING> allocate_unicode_string_object(const std::shared_ptr<emulator_t>& emulator,
	                                                                 std::wstring_view str,
	                                                                 const std::string& object_name = {});
}
