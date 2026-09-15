#pragma once
#include "../emu/addr_space.hpp"
#include "string.hpp"
#include <string>
#include <string_view>
#include <cstdint>
#include <cstdio>
#include <type_traits>

namespace guest
{

namespace detail
{

enum class length_mod { none, h, hh, l, ll, I64, I32, z };

template <typename CharT>
length_mod parse_length_mod(std::basic_string_view<CharT> fmt, std::size_t& i)
{
	if (i >= fmt.size()) return length_mod::none;

	if (fmt[i] == CharT('h'))
	{
		++i;
		if (i < fmt.size() && fmt[i] == CharT('h')) { ++i; return length_mod::hh; }
		return length_mod::h;
	}
	if (fmt[i] == CharT('l'))
	{
		++i;
		if (i < fmt.size() && fmt[i] == CharT('l')) { ++i; return length_mod::ll; }
		return length_mod::l;
	}
	if (fmt[i] == CharT('I'))
	{
		if (i + 2 < fmt.size() && fmt[i + 1] == CharT('6') && fmt[i + 2] == CharT('4'))
		{ i += 3; return length_mod::I64; }
		if (i + 2 < fmt.size() && fmt[i + 1] == CharT('3') && fmt[i + 2] == CharT('2'))
		{ i += 3; return length_mod::I32; }
	}
	if (fmt[i] == CharT('z')) { ++i; return length_mod::z; }

	return length_mod::none;
}

inline bool is_64bit(length_mod lm)
{
	return lm == length_mod::ll || lm == length_mod::I64 || lm == length_mod::z;
}

}

template <typename CharT, typename NextArg>
std::basic_string<CharT> vformat(addr_space& space, std::basic_string_view<CharT> fmt, NextArg next_arg)
{
	std::basic_string<CharT> result;
	using lm = detail::length_mod;

	constexpr auto pct = CharT('%');
	constexpr auto foreign_mod = std::is_same_v<CharT, char> ? lm::l : lm::h;

	auto append_null = [&]() {
		if constexpr (std::is_same_v<CharT, char>) result += "(null)";
		else result += u"(null)";
	};

	// Every conversion routed here prints ascii, so one narrow snprintf serves both widths.
	auto format_spec = [&](const std::string& host_spec, auto val) {
		char buf[256]{};
		std::snprintf(buf, std::size(buf), host_spec.c_str(), val);
		if constexpr (std::is_same_v<CharT, char>) result += buf;
		else result += widen_string(buf);
	};

	auto read_unicode_string = [&](addr_t ptr) {
		const auto ws = read_wstring(space,
			space.read_mem<std::uint64_t>(ptr + 8),
			space.read_mem<std::uint16_t>(ptr) / sizeof(char16_t));
		if constexpr (std::is_same_v<CharT, char>) result += narrow_wstring(ws);
		else result += ws;
	};

	auto read_native = [&](addr_t addr) {
		result += read_basic_string<CharT>(space, addr);
	};

	auto read_foreign = [&](addr_t addr) {
		if constexpr (std::is_same_v<CharT, char>)
			result += narrow_wstring(read_wstring(space, addr));
		else
			result += widen_string(read_string(space, addr));
	};

	for (std::size_t i = 0; i < fmt.size(); ++i)
	{
		if (fmt[i] != pct) { result += fmt[i]; continue; }

		const std::size_t spec_start = i;
		if (++i >= fmt.size()) break;
		if (fmt[i] == pct) { result += pct; continue; }

		std::string mods;

		while (i < fmt.size() && (fmt[i] == CharT('-') || fmt[i] == CharT('+') ||
			fmt[i] == CharT(' ') || fmt[i] == CharT('0') || fmt[i] == CharT('#')))
			mods += static_cast<char>(fmt[i++]);

		if (i < fmt.size() && fmt[i] == CharT('*'))
		{
			mods += std::to_string(static_cast<std::int32_t>(next_arg()));
			++i;
		}
		else while (i < fmt.size() && fmt[i] >= CharT('0') && fmt[i] <= CharT('9'))
			mods += static_cast<char>(fmt[i++]);

		if (i < fmt.size() && fmt[i] == CharT('.'))
		{
			mods += '.';
			++i;

			if (i < fmt.size() && fmt[i] == CharT('*'))
			{
				mods += std::to_string(static_cast<std::int32_t>(next_arg()));
				++i;
			}
			else while (i < fmt.size() && fmt[i] >= CharT('0') && fmt[i] <= CharT('9'))
				mods += static_cast<char>(fmt[i++]);
		}

		const auto length = detail::parse_length_mod<CharT>(fmt, i);
		if (i >= fmt.size()) break;

		if (fmt[i] == CharT('w') && i + 1 < fmt.size() && fmt[i + 1] == CharT('Z'))
		{
			++i;
			const auto ptr = static_cast<addr_t>(next_arg());
			if (ptr) read_unicode_string(ptr); else append_null();
			continue;
		}
		if (fmt[i] == CharT('Z'))
		{
			const auto ptr = static_cast<addr_t>(next_arg());
			if (ptr) read_unicode_string(ptr); else append_null();
			continue;
		}

		const CharT spec = fmt[i];
		const std::basic_string<CharT> spec_str(fmt.substr(spec_start, i - spec_start + 1));

		// The guest writes MSVC's spelling, where %l is four bytes and %I64 is how it says eight.
		auto host_spec = [&mods](const bool as_64bit, const CharT conv) {
			return "%" + mods + (as_64bit ? "ll" : "") + static_cast<char>(conv);
		};

		switch (spec)
		{
		case CharT('d'): case CharT('i'): case CharT('u'):
		case CharT('x'): case CharT('X'): case CharT('o'):
		{
			const auto raw = next_arg();
			if (detail::is_64bit(length))
				format_spec(host_spec(true, spec), static_cast<std::uint64_t>(raw));
			else
				format_spec(host_spec(false, spec), static_cast<std::uint32_t>(raw));
			break;
		}
		case CharT('p'):
			format_spec(host_spec(false, spec), reinterpret_cast<void*>(next_arg()));
			break;
		case CharT('s'):
		{
			const auto raw = static_cast<addr_t>(next_arg());
			if (raw) { if (length == foreign_mod) read_foreign(raw); else read_native(raw); }
			else append_null();
			break;
		}
		case CharT('S'):
		{
			const auto raw = static_cast<addr_t>(next_arg());
			if (raw) read_foreign(raw); else append_null();
			break;
		}
		case CharT('c'):
			result += static_cast<CharT>(next_arg());
			break;
		case CharT('C'):
		{
			if constexpr (std::is_same_v<CharT, char>)
				result += static_cast<char>(static_cast<char16_t>(next_arg()));
			else
				result += static_cast<char16_t>(static_cast<char>(next_arg()));
			break;
		}
		default:
			result += spec_str;
			break;
		}
	}

	return result;
}

template <typename NextArg>
std::string vsprintf(addr_space& space, std::string_view fmt, NextArg next_arg)
{
	return vformat<char>(space, fmt, std::move(next_arg));
}

template <typename NextArg>
std::u16string vswprintf(addr_space& space, std::u16string_view fmt, NextArg next_arg)
{
	return vformat<char16_t>(space, fmt, std::move(next_arg));
}

// A va_list is a pointer to consecutive 8-byte slots on both architectures.
inline auto va_list_args(addr_space& space, const addr_t va_list)
{
	return [&space, addr = va_list]() mutable -> std::uint64_t
	{
		const auto value = space.read_mem<std::uint64_t>(addr);
		addr += sizeof(std::uint64_t);
		return value;
	};
}

}
