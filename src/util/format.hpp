#pragma once
#include "../emu/addr_space.hpp"
#include "string.hpp"
#include <string>
#include <string_view>
#include <cstdint>
#include <cstdio>
#include <algorithm>

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

template <typename NextArg>
std::string vsprintf(addr_space& space, std::string_view fmt, NextArg next_arg)
{
	std::string result;
	using lm = detail::length_mod;

	for (std::size_t i = 0; i < fmt.size(); ++i)
	{
		if (fmt[i] != '%') { result += fmt[i]; continue; }

		const std::size_t spec_start = i;
		if (++i >= fmt.size()) break;
		if (fmt[i] == '%') { result += '%'; continue; }

		while (i < fmt.size() && (fmt[i] == '-' || fmt[i] == '+' ||
			fmt[i] == ' ' || fmt[i] == '0' || fmt[i] == '#'))
			++i;

		if (i < fmt.size() && fmt[i] == '*') { next_arg(); ++i; }
		else while (i < fmt.size() && fmt[i] >= '0' && fmt[i] <= '9') ++i;

		if (i < fmt.size() && fmt[i] == '.')
		{
			++i;
			if (i < fmt.size() && fmt[i] == '*') { next_arg(); ++i; }
			else while (i < fmt.size() && fmt[i] >= '0' && fmt[i] <= '9') ++i;
		}

		const auto length = detail::parse_length_mod<char>(fmt, i);
		if (i >= fmt.size()) break;

		if (fmt[i] == 'w' && i + 1 < fmt.size() && fmt[i + 1] == 'Z')
		{
			++i;
			const auto ptr = static_cast<addr_t>(next_arg());
			if (ptr)
			{
				const auto us_length = space.read_mem<std::uint16_t>(ptr);
				const auto buffer = space.read_mem<std::uint64_t>(ptr + 8);
				if (buffer && us_length)
					result += narrow_wstring(read_wstring(space, buffer, us_length / sizeof(wchar_t)));
			}
			else
				result += "(null)";
			continue;
		}
		if (fmt[i] == 'Z')
		{
			const auto ptr = static_cast<addr_t>(next_arg());
			if (ptr)
			{
				const auto us_length = space.read_mem<std::uint16_t>(ptr);
				const auto buffer = space.read_mem<std::uint64_t>(ptr + 8);
				if (buffer && us_length)
					result += narrow_wstring(read_wstring(space, buffer, us_length / sizeof(wchar_t)));
			}
			else
				result += "(null)";
			continue;
		}

		const char spec = fmt[i];
		const std::string spec_str(fmt.substr(spec_start, i - spec_start + 1));
		char buf[256]{};

		switch (spec)
		{
		case 'd': case 'i': case 'u': case 'x': case 'X': case 'o':
		{
			const auto raw = next_arg();
			if (detail::is_64bit(length))
				std::snprintf(buf, sizeof(buf), spec_str.c_str(), static_cast<std::uint64_t>(raw));
			else
				std::snprintf(buf, sizeof(buf), spec_str.c_str(), static_cast<std::uint32_t>(raw));
			result += buf;
			break;
		}
		case 'p':
		{
			const auto raw = next_arg();
			std::snprintf(buf, sizeof(buf), spec_str.c_str(), reinterpret_cast<void*>(raw));
			result += buf;
			break;
		}
		case 's':
		{
			const auto raw = static_cast<addr_t>(next_arg());
			if (raw)
			{
				if (length == lm::l)
					result += narrow_wstring(read_wstring(space, raw));
				else
					result += read_string(space, raw);
			}
			else
				result += "(null)";
			break;
		}
		case 'S':
		{
			const auto raw = static_cast<addr_t>(next_arg());
			if (raw)
				result += narrow_wstring(read_wstring(space, raw));
			else
				result += "(null)";
			break;
		}
		case 'c':
		{
			result += static_cast<char>(next_arg());
			break;
		}
		case 'C':
		{
			result += static_cast<char>(static_cast<wchar_t>(next_arg()));
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
std::wstring vswprintf(addr_space& space, std::wstring_view fmt, NextArg next_arg)
{
	std::wstring result;
	using lm = detail::length_mod;

	for (std::size_t i = 0; i < fmt.size(); ++i)
	{
		if (fmt[i] != L'%') { result += fmt[i]; continue; }

		const std::size_t spec_start = i;
		if (++i >= fmt.size()) break;
		if (fmt[i] == L'%') { result += L'%'; continue; }

		while (i < fmt.size() && (fmt[i] == L'-' || fmt[i] == L'+' ||
			fmt[i] == L' ' || fmt[i] == L'0' || fmt[i] == L'#'))
			++i;

		int width = 0;
		if (i < fmt.size() && fmt[i] == L'*') { width = static_cast<int>(next_arg()); ++i; }
		else while (i < fmt.size() && fmt[i] >= L'0' && fmt[i] <= L'9') ++i;

		int precision = -1;
		if (i < fmt.size() && fmt[i] == L'.')
		{
			++i;
			if (i < fmt.size() && fmt[i] == L'*') { precision = static_cast<int>(next_arg()); ++i; }
			else while (i < fmt.size() && fmt[i] >= L'0' && fmt[i] <= L'9') ++i;
		}

		const auto length = detail::parse_length_mod<wchar_t>(fmt, i);
		if (i >= fmt.size()) break;

		if (fmt[i] == L'w' && i + 1 < fmt.size() && fmt[i + 1] == L'Z')
		{
			++i;
			const auto ptr = static_cast<addr_t>(next_arg());
			if (ptr)
			{
				const auto us_length = space.read_mem<std::uint16_t>(ptr);
				const auto buffer = space.read_mem<std::uint64_t>(ptr + 8);
				if (buffer && us_length)
					result += read_wstring(space, buffer, us_length / sizeof(wchar_t));
			}
			else
				result += L"(null)";
			continue;
		}
		if (fmt[i] == L'Z')
		{
			const auto ptr = static_cast<addr_t>(next_arg());
			if (ptr)
			{
				const auto us_length = space.read_mem<std::uint16_t>(ptr);
				const auto buffer = space.read_mem<std::uint64_t>(ptr + 8);
				if (buffer && us_length)
					result += read_wstring(space, buffer, us_length / sizeof(wchar_t));
			}
			else
				result += L"(null)";
			continue;
		}

		const wchar_t spec = fmt[i];
		const std::wstring spec_str(fmt.substr(spec_start, i - spec_start + 1));
		wchar_t buf[256]{};

		switch (spec)
		{
		case L'd': case L'i': case L'u': case L'x': case L'X': case L'o':
		{
			const auto raw = next_arg();
			if (detail::is_64bit(length))
				std::swprintf(buf, std::size(buf), spec_str.c_str(), static_cast<std::uint64_t>(raw));
			else
				std::swprintf(buf, std::size(buf), spec_str.c_str(), static_cast<std::uint32_t>(raw));
			result += buf;
			break;
		}
		case L'p':
		{
			const auto raw = next_arg();
			std::swprintf(buf, std::size(buf), spec_str.c_str(), reinterpret_cast<void*>(raw));
			result += buf;
			break;
		}
		case L's':
		{
			const auto raw = static_cast<addr_t>(next_arg());
			if (raw)
			{
				if (length == lm::h)
					result += widen_string(read_string(space, raw));
				else
					result += read_wstring(space, raw);
			}
			else
				result += L"(null)";
			break;
		}
		case L'S':
		{
			const auto raw = static_cast<addr_t>(next_arg());
			if (raw)
				result += widen_string(read_string(space, raw));
			else
				result += L"(null)";
			break;
		}
		case L'c':
		{
			result += static_cast<wchar_t>(next_arg());
			break;
		}
		case L'C':
		{
			result += static_cast<wchar_t>(static_cast<char>(next_arg()));
			break;
		}
		default:
			result += spec_str;
			break;
		}
	}

	return result;
}

}
