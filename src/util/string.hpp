#pragma once
#include "../emu/addr_space.hpp"
#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

struct string_view_hash
{
	using is_transparent = void;
	size_t operator()(std::string_view s) const { return std::hash<std::string_view>{}(s); }
};

// NT folds case against its own upcase table rather than the host locale, which
// differs from either above ascii -- and ascii is the whole of what a guest
// driver names. Folding here rather than reaching for a CRT routine also keeps
// one spelling: _stricmp and _wcsnicmp are MSVC's, strcasecmp and wcsncasecmp
// are POSIX's, and neither pair exists for char16_t at all.
constexpr char ascii_lower(const char c)
{
	return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}

constexpr char16_t ascii_lower(const char16_t c)
{
	return c >= u'A' && c <= u'Z' ? static_cast<char16_t>(c - u'A' + u'a') : c;
}

inline std::string ascii_lower(const std::string_view s)
{
	std::string out(s);
	for (auto& c : out)
		c = ascii_lower(c);
	return out;
}

// The sign of the first folded difference, which is all the Rtl and CRT
// comparisons promise. Bounded by `count`, so neither side is read past its end
// -- a counted guest string is very often not terminated at all.
template <typename T>
constexpr int compare_ascii_nocase(const T* const a, const T* const b, const std::size_t count)
{
	for (std::size_t i = 0; i < count; ++i)
	{
		const auto ca = ascii_lower(a[i]);
		const auto cb = ascii_lower(b[i]);

		if (ca != cb)
			return ca < cb ? -1 : 1;
	}

	return 0;
}

// The whole of both strings: a shared prefix leaves the shorter one the lesser,
// which the bounded compare above cannot say on its own.
template <typename T>
constexpr int compare_ascii_nocase(const std::basic_string_view<T> a, const std::basic_string_view<T> b)
{
	if (const auto diff = compare_ascii_nocase(a.data(), b.data(), std::min(a.size(), b.size())))
		return diff;

	if (a.size() == b.size())
		return 0;

	return a.size() < b.size() ? -1 : 1;
}

inline std::string narrow_wstring(std::u16string_view wide)
{
	std::string result;
	result.reserve(wide.size());
	for (const auto wc : wide)
		result += static_cast<char>(wc & 0xFF);
	return result;
}

inline std::u16string widen_string(std::string_view narrow)
{
	std::u16string result;
	result.reserve(narrow.size());
	for (const auto c : narrow)
		result += static_cast<char16_t>(static_cast<unsigned char>(c));
	return result;
}

namespace guest
{

template <typename T>
std::basic_string<T> read_basic_string(addr_space& space, addr_t addr, std::size_t max_chars = 4096)
{
	std::basic_string<T> result;
	for (std::size_t i = 0; i < max_chars; ++i)
	{
		const T c = space.read_mem<T>(addr + i * sizeof(T));
		if (c == T{}) break;
		result += c;
	}
	return result;
}

inline std::string read_string(addr_space& space, addr_t addr, std::size_t max_chars = 4096)
{
	return read_basic_string<char>(space, addr, max_chars);
}

inline std::u16string read_wstring(addr_space& space, addr_t addr, std::size_t max_chars = 4096)
{
	return read_basic_string<char16_t>(space, addr, max_chars);
}

template <typename T>
void write_basic_string_buffer(addr_space& space, addr_t addr, std::size_t buf_count, std::basic_string_view<T> str)
{
	const std::size_t chars = std::min(str.size(), buf_count - 1);
	if (chars > 0)
		space.write_mem(addr, str.data(), chars * sizeof(T));
	constexpr T terminator{};
	space.write_mem<T>(addr + chars * sizeof(T), terminator);
}

inline void write_string_buffer(addr_space& space, addr_t addr, std::size_t buf_count, std::string_view str)
{
	write_basic_string_buffer<char>(space, addr, buf_count, str);
}

inline void write_wstring_buffer(addr_space& space, addr_t addr, std::size_t buf_count, std::u16string_view str)
{
	write_basic_string_buffer<char16_t>(space, addr, buf_count, str);
}

// Space is anything exposing addr_space's alloc/write_mem interface, so guest strings
// can be placed either by the raw address space or by a tracking allocator
template <typename T, typename Space>
addr_t allocate_basic_string(Space& space, std::basic_string_view<T> str, bool terminate = true)
{
	const std::size_t byte_size = str.size() * sizeof(T) + (terminate ? sizeof(T) : 0);
	const auto addr = space.alloc(byte_size, prot_rw);
	space.write_mem(addr, str.data(), str.size() * sizeof(T));
	if (terminate)
	{
		constexpr T terminator{};
		space.template write_mem<T>(addr + str.size() * sizeof(T), terminator);
	}
	return addr;
}

template <typename Space>
addr_t allocate_string(Space& space, std::string_view str, bool terminate = true)
{
	return allocate_basic_string<char>(space, str, terminate);
}

template <typename Space>
addr_t allocate_wstring(Space& space, std::u16string_view str, bool terminate = true)
{
	return allocate_basic_string<char16_t>(space, str, terminate);
}

}
