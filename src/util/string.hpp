#pragma once
#include "../emu/addr_space.hpp"
#include <string>
#include <string_view>

struct string_view_hash
{
	using is_transparent = void;
	size_t operator()(std::string_view s) const { return std::hash<std::string_view>{}(s); }
};

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

inline std::wstring read_wstring(addr_space& space, addr_t addr, std::size_t max_chars = 4096)
{
	return read_basic_string<wchar_t>(space, addr, max_chars);
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

inline void write_wstring_buffer(addr_space& space, addr_t addr, std::size_t buf_count, std::wstring_view str)
{
	write_basic_string_buffer<wchar_t>(space, addr, buf_count, str);
}

template <typename T>
addr_t allocate_basic_string(addr_space& space, std::basic_string_view<T> str, bool terminate = true)
{
	const std::size_t byte_size = str.size() * sizeof(T) + (terminate ? sizeof(T) : 0);
	const auto addr = space.alloc(byte_size, prot_rw);
	space.write_mem(addr, str.data(), str.size() * sizeof(T));
	if (terminate)
	{
		constexpr T terminator{};
		space.write_mem<T>(addr + str.size() * sizeof(T), terminator);
	}
	return addr;
}

inline addr_t allocate_string(addr_space& space, std::string_view str, bool terminate = true)
{
	return allocate_basic_string<char>(space, str, terminate);
}

inline addr_t allocate_wstring(addr_space& space, std::wstring_view str, bool terminate = true)
{
	return allocate_basic_string<wchar_t>(space, str, terminate);
}

}
