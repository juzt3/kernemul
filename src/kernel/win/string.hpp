#pragma once
#include "types.hpp"
#include "win_user_mem.hpp"
#include "../../emu/object.hpp"
#include "../../util/string.hpp"
#include <algorithm>
#include <cwchar>

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

inline std::wstring read_unicode_string(addr_space& space, const _UNICODE_STRING& str)
{
	return read_counted_string<wchar_t>(space, str);
}

inline std::string read_ansi_string(addr_space& space, const _STRING& str)
{
	return read_counted_string<char>(space, str);
}

inline std::wstring read_unicode_string(const emu_object<_UNICODE_STRING>& str)
{
	return str ? read_unicode_string(*str.space(), str.read()) : std::wstring{};
}

inline std::string read_ansi_string(const emu_object<_STRING>& str)
{
	return str ? read_ansi_string(*str.space(), str.read()) : std::string{};
}

// What RtlCompareUnicodeString promises is only the sign of the result, so the
// ordering itself comes from the library: std compares lexicographically, and
// the CRT folds case. NT folds against its own upcase table rather than the
// host locale, which differs from this above ascii -- and ascii is the whole of
// what a guest driver names.
inline int compare_unicode(std::wstring_view a, std::wstring_view b,
	const bool case_insensitive)
{
	if (!case_insensitive)
		return a.compare(b);

	// Bounded by the shorter of the two, so neither view is read past its end.
	if (const auto diff = _wcsnicmp(a.data(), b.data(), std::min(a.size(), b.size())))
		return diff;

	return static_cast<int>(a.size()) - static_cast<int>(b.size());
}

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
