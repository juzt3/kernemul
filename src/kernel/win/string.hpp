#pragma once
#include "types.hpp"
#include "win_user_mem.hpp"
#include "../../emu/object.hpp"
#include "../../util/string.hpp"

namespace win
{

template <typename Space>
inline _UNICODE_STRING init_unicode_string(Space& space, std::wstring_view str)
{
	const addr_t buffer = guest::allocate_wstring(space, str);
	const auto length = static_cast<unsigned short>(str.size() * sizeof(wchar_t));
	return _UNICODE_STRING{
		.Length = length,
		.MaximumLength = static_cast<unsigned short>(length + sizeof(wchar_t)),
		.Buffer = guest_ptr<wchar_t>(buffer)
	};
}

inline emu_object<_UNICODE_STRING> allocate_unicode_string(addr_space& space, std::wstring_view str, std::string name = {})
{
	const auto us = init_unicode_string(space, str);
	auto obj = emu_object<_UNICODE_STRING>::allocate(space, std::move(name));
	obj.write(us);
	return obj;
}

}
