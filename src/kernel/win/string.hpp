#pragma once
#include "types.hpp"
#include "../../emu/object.hpp"
#include "../../util/string.hpp"

namespace win
{

inline UNICODE_STRING init_unicode_string(addr_space& space, std::wstring_view str)
{
	const addr_t buffer = guest::allocate_wstring(space, str);
	const auto length = static_cast<std::uint16_t>(str.size() * sizeof(wchar_t));
	return UNICODE_STRING{
		.Length = length,
		.MaximumLength = static_cast<std::uint16_t>(length + sizeof(wchar_t)),
		.Buffer = reinterpret_cast<wchar_t*>(buffer)
	};
}

inline emu_object<UNICODE_STRING> allocate_unicode_string(addr_space& space, std::wstring_view str, std::string name = {})
{
	const auto us = init_unicode_string(space, str);
	auto obj = emu_object<UNICODE_STRING>::allocate(space, std::move(name));
	obj.write(us);
	return obj;
}

}
