#pragma once
#include "types.hpp"
#include "win_user_mem.hpp"
#include "../../emu/object.hpp"
#include "../../util/string.hpp"
#include <algorithm>

namespace win
{

// A counted string is a length in bytes and a pointer. Neither the terminator
// nor anything past Length is part of it -- the buffer is very often not
// terminated at all -- so this is not guest::read_wstring's job.
template <typename T, typename S>
std::basic_string<T> read_counted_string(addr_space& space, const S& str)
{
	if (!str.Length || !str.Buffer)
		return {};

	std::basic_string<T> out(str.Length / sizeof(T), T{});
	space.read_mem(guest_va(str.Buffer), out.data(), str.Length);

	return out;
}

inline std::u16string read_unicode_string(addr_space& space, const _UNICODE_STRING& str)
{
	return read_counted_string<char16_t>(space, str);
}

inline std::string read_ansi_string(addr_space& space, const _STRING& str)
{
	return read_counted_string<char>(space, str);
}

inline std::u16string read_unicode_string(const emu_object<_UNICODE_STRING>& str)
{
	return str ? read_unicode_string(*str.space(), str.read()) : std::u16string{};
}

inline std::string read_ansi_string(const emu_object<_STRING>& str)
{
	return str ? read_ansi_string(*str.space(), str.read()) : std::string{};
}

// What RtlCompareUnicodeString promises is only the sign of the result. The
// ordering comes from the library when the compare is exact, and from
// compare_ascii_nocase when it folds -- see there for why NT's folding is not
// the host CRT's.
inline int compare_unicode(std::u16string_view a, std::u16string_view b,
	const bool case_insensitive)
{
	return case_insensitive ? compare_ascii_nocase(a, b) : a.compare(b);
}

template <typename Space>
inline _UNICODE_STRING init_unicode_string(Space& space, std::u16string_view str)
{
	const addr_t buffer = guest::allocate_wstring(space, str);
	const auto length = static_cast<unsigned short>(str.size() * sizeof(char16_t));
	return _UNICODE_STRING{
		.Length = length,
		.MaximumLength = static_cast<unsigned short>(length + sizeof(char16_t)),
		.Buffer = guest_ptr<char16_t>(buffer)
	};
}

inline emu_object<_UNICODE_STRING> allocate_unicode_string(addr_space& space, std::u16string_view str, std::string name = {})
{
	const auto us = init_unicode_string(space, str);
	auto obj = emu_object<_UNICODE_STRING>::allocate(space, std::move(name));
	obj.write(us);
	return obj;
}

}
