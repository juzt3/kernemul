#include "nt_helpers.hpp"

std::wstring guest_vswprintf(const emulator_t& emulator, const std::wstring_view format,
	const emulator_t::address_type va_list_address)
{
	std::wstring result;
	std::size_t arg_index = 0;

	for (std::size_t i = 0; i < format.size(); ++i)
	{
		if (format[i] != L'%')
		{
			result += format[i];

			continue;
		}

		const std::size_t spec_start = i;

		++i;

		if (i >= format.size())
		{
			break;
		}

		if (format[i] == L'%')
		{
			result += L'%';

			continue;
		}

		while (i < format.size() && (format[i] == L'-' || format[i] == L'+' ||
			format[i] == L' ' || format[i] == L'0' || format[i] == L'#'))
		{
			++i;
		}

		int width = 0;

		if (i < format.size() && format[i] == L'*')
		{
			width = static_cast<int>(read_guest_vararg(emulator, va_list_address, arg_index));
			++i;
		}
		else
		{
			while (i < format.size() && format[i] >= L'0' && format[i] <= L'9')
			{
				++i;
			}
		}

		int precision = -1;

		if (i < format.size() && format[i] == L'.')
		{
			++i;

			if (i < format.size() && format[i] == L'*')
			{
				precision = static_cast<int>(read_guest_vararg(emulator, va_list_address, arg_index));
				++i;
			}
			else
			{
				while (i < format.size() && format[i] >= L'0' && format[i] <= L'9')
				{
					++i;
				}
			}
		}

		enum class length_mod_t { none, h, hh, l, ll, I64, I32, z };
		length_mod_t length_mod = length_mod_t::none;

		if (i < format.size())
		{
			if (format[i] == L'h')
			{
				length_mod = length_mod_t::h;
				++i;

				if (i < format.size() && format[i] == L'h')
				{
					length_mod = length_mod_t::hh;
					++i;
				}
			}
			else if (format[i] == L'l')
			{
				length_mod = length_mod_t::l;
				++i;

				if (i < format.size() && format[i] == L'l')
				{
					length_mod = length_mod_t::ll;
					++i;
				}
			}
			else if (format[i] == L'I')
			{
				if (i + 2 < format.size() && format[i + 1] == L'6' && format[i + 2] == L'4')
				{
					length_mod = length_mod_t::I64;
					i += 3;
				}
				else if (i + 2 < format.size() && format[i + 1] == L'3' && format[i + 2] == L'2')
				{
					length_mod = length_mod_t::I32;
					i += 3;
				}
			}
			else if (format[i] == L'z')
			{
				length_mod = length_mod_t::z;
				++i;
			}
		}

		if (i >= format.size())
		{
			break;
		}

		// handle %wZ / %Z (UNICODE_STRING pointer) - Windows kernel-specific format
		{
			bool is_unicode_string = false;

			if (i < format.size() && format[i] == L'w' && (i + 1) < format.size() && format[i + 1] == L'Z')
			{
				i += 1; // advance to 'Z'
				is_unicode_string = true;
			}
			else if (i < format.size() && format[i] == L'Z')
			{
				is_unicode_string = true;
			}

			if (is_unicode_string)
			{
				const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

				if (raw_arg)
				{
					try
					{
						UNICODE_STRING us = {};
						static_cast<void>(emulator.read_virtual_memory(raw_arg, &us, sizeof(us)));
						const auto buf_addr = reinterpret_cast<emulator_t::address_type>(us.Buffer);

						if (buf_addr && us.Length)
						{
							result += kernel::read_guest_wstring(emulator, buf_addr);
						}
					}
					catch (...)
					{
						result += L"(unreadable)";
					}
				}
				else
				{
					result += L"(null)";
				}

				continue;
			}
		}

		const wchar_t specifier = format[i];
		const std::wstring spec_str(format.substr(spec_start, i - spec_start + 1));

		wchar_t buffer[256] = { };

		switch (specifier)
		{
		case L'd':
		case L'i':
		case L'u':
		case L'x':
		case L'X':
		case L'o':
		{
			const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

			switch (length_mod)
			{
			case length_mod_t::ll:
			case length_mod_t::I64:
			case length_mod_t::z:
				swprintf(buffer, std::size(buffer), spec_str.c_str(), static_cast<std::uint64_t>(raw_arg));
				break;
			default:
				swprintf(buffer, std::size(buffer), spec_str.c_str(), static_cast<std::uint32_t>(raw_arg));
				break;
			}

			result += buffer;

			break;
		}
		case L'p':
		{
			const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

			swprintf(buffer, std::size(buffer), spec_str.c_str(), reinterpret_cast<void*>(raw_arg));

			result += buffer;

			break;
		}
		case L's':
		{
			const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

			if (raw_arg)
			{
				try
				{
					if (length_mod == length_mod_t::h)
					{
						result += util::widen_string(kernel::read_guest_string(emulator, raw_arg));
					}
					else
					{
						result += kernel::read_guest_wstring(emulator, raw_arg);
					}
				}
				catch (...)
				{
					result += L"(unreadable)";
				}
			}
			else
			{
				result += L"(null)";
			}

			break;
		}
		case L'S':
		{
			const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

			if (raw_arg)
			{
				try
				{
					const auto narrow = kernel::read_guest_string(emulator, raw_arg);

					result += util::widen_string(narrow);
				}
				catch (...)
				{
					result += L"(unreadable)";
				}
			}
			else
			{
				result += L"(null)";
			}

			break;
		}
		case L'c':
		{
			const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

			result += static_cast<wchar_t>(raw_arg);

			break;
		}
		case L'C':
		{
			const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

			result += static_cast<wchar_t>(static_cast<char>(raw_arg));

			break;
		}
		default:
		{
			result += spec_str;

			break;
		}
		}
	}

	return result;
}

std::string guest_vsprintf(const emulator_t& emulator, const std::string_view format,
	const emulator_t::address_type va_list_address)
{
	std::string result;
	std::size_t arg_index = 0;

	for (std::size_t i = 0; i < format.size(); ++i)
	{
		if (format[i] != '%')
		{
			result += format[i];

			continue;
		}

		const std::size_t spec_start = i;

		++i;

		if (i >= format.size())
		{
			break;
		}

		if (format[i] == '%')
		{
			result += '%';

			continue;
		}

		while (i < format.size() && (format[i] == '-' || format[i] == '+' ||
		       format[i] == ' ' || format[i] == '0' || format[i] == '#'))
		{
			++i;
		}

		if (i < format.size() && format[i] == '*')
		{
			read_guest_vararg(emulator, va_list_address, arg_index);
			++i;
		}
		else
		{
			while (i < format.size() && format[i] >= '0' && format[i] <= '9')
			{
				++i;
			}
		}

		if (i < format.size() && format[i] == '.')
		{
			++i;

			if (i < format.size() && format[i] == '*')
			{
				read_guest_vararg(emulator, va_list_address, arg_index);
				++i;
			}
			else
			{
				while (i < format.size() && format[i] >= '0' && format[i] <= '9')
				{
					++i;
				}
			}
		}

		enum class length_mod_t { none, h, hh, l, ll, I64, I32, z };
		length_mod_t length_mod = length_mod_t::none;

		if (i < format.size())
		{
			if (format[i] == 'h')
			{
				length_mod = length_mod_t::h;
				++i;

				if (i < format.size() && format[i] == 'h')
				{
					length_mod = length_mod_t::hh;
					++i;
				}
			}
			else if (format[i] == 'l')
			{
				length_mod = length_mod_t::l;
				++i;

				if (i < format.size() && format[i] == 'l')
				{
					length_mod = length_mod_t::ll;
					++i;
				}
			}
			else if (format[i] == 'I')
			{
				if (i + 2 < format.size() && format[i + 1] == '6' && format[i + 2] == '4')
				{
					length_mod = length_mod_t::I64;
					i += 3;
				}
				else if (i + 2 < format.size() && format[i + 1] == '3' && format[i + 2] == '2')
				{
					length_mod = length_mod_t::I32;
					i += 3;
				}
			}
			else if (format[i] == 'z')
			{
				length_mod = length_mod_t::z;
				++i;
			}
		}

		if (i >= format.size())
		{
			break;
		}

		const char specifier = format[i];
		const std::string spec_str(format.substr(spec_start, i - spec_start + 1));

		char buffer[256] = { };

		switch (specifier)
		{
		case 'd':
		case 'i':
		case 'u':
		case 'x':
		case 'X':
		case 'o':
		{
			const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

			switch (length_mod)
			{
			case length_mod_t::ll:
			case length_mod_t::I64:
			case length_mod_t::z:
				snprintf(buffer, std::size(buffer), spec_str.c_str(), static_cast<std::uint64_t>(raw_arg));
				break;
			default:
				snprintf(buffer, std::size(buffer), spec_str.c_str(), static_cast<std::uint32_t>(raw_arg));
				break;
			}

			result += buffer;

			break;
		}
		case 'p':
		{
			const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

			snprintf(buffer, std::size(buffer), spec_str.c_str(), reinterpret_cast<void*>(raw_arg));

			result += buffer;

			break;
		}
		case 's':
		{
			const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

			if (raw_arg)
			{
				try
				{
					if (length_mod == length_mod_t::l)
					{
						const auto wide = kernel::read_guest_wstring(emulator, raw_arg);

						result += util::narrow_wstring(wide);
					}
					else
					{
						result += kernel::read_guest_string(emulator, raw_arg);
					}
				}
				catch (...)
				{
					result += "(unreadable)";
				}
			}
			else
			{
				result += "(null)";
			}

			break;
		}
		case 'S':
		{
			const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

			if (raw_arg)
			{
				try
				{
					const auto wide = kernel::read_guest_wstring(emulator, raw_arg);

					result += util::narrow_wstring(wide);
				}
				catch (...)
				{
					result += "(unreadable)";
				}
			}
			else
			{
				result += "(null)";
			}

			break;
		}
		case 'c':
		{
			const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

			result += static_cast<char>(raw_arg);

			break;
		}
		case 'C':
		{
			const auto raw_arg = read_guest_vararg(emulator, va_list_address, arg_index);

			result += static_cast<char>(static_cast<wchar_t>(raw_arg));

			break;
		}
		default:
		{
			result += spec_str;

			break;
		}
		}
	}

	return result;
}

// DbgPrint(PCSTR Format, ...)
static void handle_dbg_print(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type format_address, std::uint64_t arg1,
	std::uint64_t arg2, std::uint64_t arg3)
{
	const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

	// spill rdx/r8/r9 into shadow space to form contiguous va_list at rsp+0x10
	const emulator_t::address_type va_list_address = rsp + 0x10;

	emulator->write_virtual_memory(rsp + 0x10, &arg1, sizeof(arg1)).throw_if("write memory");
	emulator->write_virtual_memory(rsp + 0x18, &arg2, sizeof(arg2)).throw_if("write memory");
	emulator->write_virtual_memory(rsp + 0x20, &arg3, sizeof(arg3)).throw_if("write memory");

	const auto format_string = kernel::read_guest_string(*emulator, format_address);
	const auto formatted = guest_vsprintf(*emulator, format_string, va_list_address);

	THREAD_LOG("DbgPrint: {}", formatted);

	write_nt_success(emulator);
}

// DbgPrintEx(ULONG ComponentId, ULONG Level, PCSTR Format, ...)
static void handle_dbg_print_ex(const std::shared_ptr<emulator_t>& emulator,
	std::uint32_t component_id, std::uint32_t level,
	emulator_t::address_type format_address, std::uint64_t arg3)
{
	const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

	const emulator_t::address_type va_list_address = rsp + 0x20;
	emulator->write_virtual_memory(va_list_address, &arg3, sizeof(arg3)).throw_if("write memory");

	const auto format_string = kernel::read_guest_string(*emulator, format_address);
	const auto formatted = guest_vsprintf(*emulator, format_string, va_list_address);

	THREAD_LOG("DbgPrintEx called (component={}, level={}) : {}", component_id, level, formatted);

	write_nt_success(emulator);
}

// vswprintf_s(wchar_t* buffer, size_t sizeInWords, const wchar_t* format, va_list argptr)
static void handle_vswprintf_s(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type buffer, std::uint64_t size_in_words,
	emulator_t::address_type format_address, emulator_t::address_type va_list_address)
{
	if (!buffer || !size_in_words || !format_address)
	{
		THREAD_WARN_LOG("vswprintf_s called with invalid parameters");

		write_return_value(emulator, static_cast<std::uint64_t>(-1));

		return;
	}

	const auto format_string = kernel::read_guest_wstring(*emulator, format_address);
	const auto formatted = guest_vswprintf(*emulator, format_string, va_list_address);

	if (formatted.size() >= size_in_words)
	{
		constexpr wchar_t null_terminator = L'\0';

		const emulator_err_t error = emulator->write_virtual_memory(
			buffer, &null_terminator, sizeof(null_terminator));

		error.throw_if("write memory");

		THREAD_WARN_LOG("vswprintf_s called (result truncated, format='{}')",
			util::narrow_wstring(format_string));

		write_return_value(emulator, static_cast<std::uint64_t>(-1));

		return;
	}

	write_guest_wstring_buffer(*emulator, buffer, size_in_words, formatted);

	THREAD_LOG("vswprintf_s called (result='{}')",
		util::narrow_wstring(formatted));

	write_return_value(emulator, static_cast<std::uint64_t>(formatted.size()));
}

// swprintf_s(wchar_t* buffer, size_t sizeInWords, const wchar_t* format, ...)
static void handle_swprintf_s(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type buffer, std::uint64_t size_in_words,
	emulator_t::address_type format_address, std::uint64_t arg3)
{
	const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

	// spill r9 into its shadow space slot so va_list at rsp+0x20 is contiguous
	const emulator_t::address_type va_list_address = rsp + 0x20;

	const emulator_err_t spill_error = emulator->write_virtual_memory(
		va_list_address, &arg3, sizeof(arg3));

	spill_error.throw_if("write memory");

	if (!buffer || !size_in_words || !format_address)
	{
		THREAD_WARN_LOG("swprintf_s called with invalid parameters");

		write_return_value(emulator, static_cast<std::uint64_t>(-1));

		return;
	}

	const auto format_string = kernel::read_guest_wstring(*emulator, format_address);
	const auto formatted = guest_vswprintf(*emulator, format_string, va_list_address);

	if (formatted.size() >= size_in_words)
	{
		constexpr wchar_t null_terminator = L'\0';

		const emulator_err_t error = emulator->write_virtual_memory(
			buffer, &null_terminator, sizeof(null_terminator));

		error.throw_if("write memory");

		THREAD_WARN_LOG("swprintf_s called (result truncated, format='{}')",
			util::narrow_wstring(format_string));

		write_return_value(emulator, static_cast<std::uint64_t>(-1));

		return;
	}

	write_guest_wstring_buffer(*emulator, buffer, size_in_words, formatted);

	THREAD_LOG("swprintf_s called (result='{}')",
		util::narrow_wstring(formatted));

	write_return_value(emulator, static_cast<std::uint64_t>(formatted.size()));
}

// _snwprintf(wchar_t* buffer, size_t count, const wchar_t* format, ...)
static void handle_snwprintf(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type buffer_address, std::uint64_t count,
	emulator_t::address_type format_address, std::uint64_t arg3)
{
	const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
	const auto va_list_address = rsp + 0x20;

	emulator_err_t error = emulator->write_virtual_memory(
		va_list_address, &arg3, sizeof(arg3));
	error.throw_if("_snwprintf: write r9");

	if (!buffer_address || !format_address)
	{
		write_return_value(emulator, static_cast<std::uint64_t>(-1));
		return;
	}

	const auto format_string = kernel::read_guest_wstring(*emulator, format_address);
	const auto formatted = guest_vswprintf(*emulator, format_string, va_list_address);

	if (formatted.size() >= count)
	{
		write_guest_wstring_buffer(*emulator, buffer_address, count, formatted.substr(0, count > 0 ? count - 1 : 0));
		THREAD_LOG("_snwprintf called (result truncated, format='{}')", util::narrow_wstring(format_string));
		write_return_value(emulator, static_cast<std::uint64_t>(-1));
		return;
	}

	write_guest_wstring_buffer(*emulator, buffer_address, count, formatted);

	THREAD_LOG("_snwprintf called (result='{}')", util::narrow_wstring(formatted));

	write_return_value(emulator, static_cast<std::uint64_t>(formatted.size()));
}

// _vsnwprintf(wchar_t* buffer, size_t count, const wchar_t* format, va_list argptr)
static void handle_vsnwprintf(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type buffer, std::uint64_t count,
	emulator_t::address_type format_address, emulator_t::address_type va_list_address)
{
	if (!format_address)
	{
		THREAD_WARN_LOG("_vsnwprintf called with null format");

		write_return_value(emulator, static_cast<std::uint64_t>(-1));

		return;
	}

	if (count && !buffer)
	{
		THREAD_WARN_LOG("_vsnwprintf called with null dest but nonzero count");

		write_return_value(emulator, static_cast<std::uint64_t>(-1));

		return;
	}

	try
	{
		const auto format_string = kernel::read_guest_wstring(*emulator, format_address);
		const auto formatted = guest_vswprintf(*emulator, format_string, va_list_address);

		if (!buffer || !count)
		{
			THREAD_LOG("_vsnwprintf called with null dest (format='{}', would need {} chars)",
				util::narrow_wstring(format_string), formatted.size());

			write_return_value(emulator, static_cast<std::uint64_t>(formatted.size()));

			return;
		}

		if (formatted.size() >= count)
		{
			write_guest_wstring_buffer(*emulator, buffer, count + 1, formatted.substr(0, count));

			THREAD_WARN_LOG("_vsnwprintf called (result truncated, format='{}')",
				util::narrow_wstring(format_string));

			write_return_value(emulator, static_cast<std::uint64_t>(-1));

			return;
		}

		write_guest_wstring_buffer(*emulator, buffer, count, formatted);

		THREAD_LOG("_vsnwprintf called (result='{}')",
			util::narrow_wstring(formatted));

		write_return_value(emulator, static_cast<std::uint64_t>(formatted.size()));
	}
	catch (const std::exception& e)
	{
		THREAD_WARN_LOG("_vsnwprintf failed (format_addr=0x{:X}): {}", format_address, e.what());

		write_return_value(emulator, static_cast<std::uint64_t>(-1));
	}
}

// _vsnwprintf_s(wchar_t* buffer, size_t sizeInWords, size_t maxCount, const wchar_t* format, va_list argptr)
static void handle_vsnwprintf_s(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type dst_buf, std::uint64_t size_in_words,
	std::uint64_t max_count, emulator_t::address_type format_address,
	emulator_t::address_type va_list_address)
{
	if (!format_address)
	{
		THREAD_WARN_LOG("_vsnwprintf_s called with null format");
		write_return_value(emulator, static_cast<std::uint64_t>(-1));
		return;
	}

	if (!max_count && !dst_buf && !size_in_words)
	{
		write_return_value(emulator, 0);
		return;
	}

	if (!dst_buf || !size_in_words)
	{
		THREAD_WARN_LOG("_vsnwprintf_s called with null dest or zero size");
		write_return_value(emulator, static_cast<std::uint64_t>(-1));
		return;
	}

	const auto format_string = kernel::read_guest_wstring(*emulator, format_address);
	const auto formatted = guest_vswprintf(*emulator, format_string, va_list_address);

	const auto effective_size = (size_in_words > max_count) ? max_count + 1 : size_in_words;

	if (formatted.size() >= effective_size)
	{
		constexpr wchar_t null_terminator = L'\0';
		static_cast<void>(emulator->write_virtual_memory(dst_buf, &null_terminator, sizeof(null_terminator)));

		THREAD_WARN_LOG("_vsnwprintf_s called (result truncated, format='{}')",
			util::narrow_wstring(format_string));

		write_return_value(emulator, static_cast<std::uint64_t>(-1));
		return;
	}

	write_guest_wstring_buffer(*emulator, dst_buf, effective_size, formatted);

	THREAD_LOG("_vsnwprintf_s called (result='{}')", util::narrow_wstring(formatted));

	write_return_value(emulator, static_cast<std::uint64_t>(formatted.size()));
}

// _vsnprintf_s(char* buffer, size_t sizeInBytes, size_t maxCount, const char* format, va_list argptr)
static void handle_vsnprintf_s(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type dst_buf, std::uint64_t size_in_bytes,
	std::uint64_t max_count, emulator_t::address_type format_address,
	emulator_t::address_type va_list_address)
{
	if (!format_address)
	{
		THREAD_WARN_LOG("_vsnprintf_s called with null format");
		write_return_value(emulator, static_cast<std::uint64_t>(-1));
		return;
	}

	if (!max_count && !dst_buf && !size_in_bytes)
	{
		write_return_value(emulator, 0);
		return;
	}

	if (!dst_buf || !size_in_bytes)
	{
		THREAD_WARN_LOG("_vsnprintf_s called with null dest or zero size");
		write_return_value(emulator, static_cast<std::uint64_t>(-1));
		return;
	}

	const auto format_string = kernel::read_guest_string(*emulator, format_address);
	const auto formatted = guest_vsprintf(*emulator, format_string, va_list_address);

	const auto effective_size = (size_in_bytes > max_count) ? max_count + 1 : size_in_bytes;

	if (formatted.size() >= effective_size)
	{
		constexpr char null_terminator = '\0';
		static_cast<void>(emulator->write_virtual_memory(dst_buf, &null_terminator, sizeof(null_terminator)));

		THREAD_WARN_LOG("_vsnprintf_s called (result truncated, format='{}')", format_string);

		write_return_value(emulator, static_cast<std::uint64_t>(-1));
		return;
	}

	const std::size_t chars_to_write = formatted.size();
	if (chars_to_write > 0)
	{
		const emulator_err_t error = emulator->write_virtual_memory(
			dst_buf, formatted.data(), chars_to_write);
		error.throw_if("write memory");
	}

	constexpr char null_terminator = '\0';
	const emulator_err_t error = emulator->write_virtual_memory(
		dst_buf + chars_to_write, &null_terminator, sizeof(null_terminator));
	error.throw_if("write memory");

	THREAD_LOG("_vsnprintf_s called (result='{}')", formatted);

	write_return_value(emulator, static_cast<std::uint64_t>(formatted.size()));
}

void redirect_ntoskrnl_format_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_dbg_print>(emulator, mapped_image, "DbgPrint");
	redirect_handler<handle_dbg_print_ex>(emulator, mapped_image, "DbgPrintEx");
	redirect_handler<handle_vswprintf_s>(emulator, mapped_image, "vswprintf_s");
	redirect_handler<handle_swprintf_s>(emulator, mapped_image, "swprintf_s");
	redirect_handler<handle_snwprintf>(emulator, mapped_image, "_snwprintf");
	redirect_handler<handle_vsnwprintf>(emulator, mapped_image, "_vsnwprintf");
	redirect_handler<handle_vsnwprintf_s>(emulator, mapped_image, "_vsnwprintf_s");
	redirect_handler<handle_vsnprintf_s>(emulator, mapped_image, "_vsnprintf_s");
}
