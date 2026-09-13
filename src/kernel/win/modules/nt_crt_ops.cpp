#include "nt_crt_ops.hpp"
#include "../win_kernel.hpp"
#include "../../../util/format.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <cstring>
#include <cwchar>
#include <cwctype>

namespace
{

// EINVAL and ERANGE as the CRT's _s routines report them. Returned rather than
// thrown: a guest cannot be handed a host exception, and the constraint handler
// that would normally fire is the caller's to install.
constexpr std::int32_t crt_einval = 22;
constexpr std::int32_t crt_erange = 34;

}

// ntoskrnl exports a slice of the CRT, and a driver linking against it expects
// those to behave exactly as they do in user mode. Every one of these is a pure
// function over guest memory with a host equivalent, so the host CRT does the
// work and these only move the arguments and results across.
//
// The pointer-returning ones return a *guest* address: the host copy the string
// was read into is gone by the time the guest looks at it, so anything pointing
// into a string has to be expressed as an offset from where the guest's own
// copy lives.
void modules::register_ntoskrnl_crt_ops(win_kernel_state& state, proc_module& mod)
{
	state.redirect(mod, "wcslen", [](vcpu&, std::wstring str) -> std::uint64_t
	{
		THREAD_LOG_INFO("wcslen('{}') -> {}", narrow_wstring(str), str.size());
		return str.size();
	});

	state.redirect(mod, "strcmp",
		[](vcpu&, std::string str1, std::string str2) -> std::int32_t
		{
			const auto r = std::strcmp(str1.c_str(), str2.c_str());
			THREAD_LOG_INFO("strcmp('{}', '{}') -> {}", str1, str2, r);
			return r;
		});

	state.redirect(mod, "strncmp",
		[](vcpu&, std::string str1, std::string str2, const std::uint64_t count) -> std::int32_t
		{
			const auto r = std::strncmp(str1.c_str(), str2.c_str(), count);
			THREAD_LOG_INFO("strncmp('{}', '{}', {}) -> {}", str1, str2, count, r);
			return r;
		});

	state.redirect(mod, "_stricmp",
		[](vcpu&, std::string str1, std::string str2) -> std::int32_t
		{
			const auto r = _stricmp(str1.c_str(), str2.c_str());
			THREAD_LOG_INFO("_stricmp('{}', '{}') -> {}", str1, str2, r);
			return r;
		});

	state.redirect(mod, "_strnicmp",
		[](vcpu&, std::string str1, std::string str2, const std::uint64_t count) -> std::int32_t
		{
			const auto r = _strnicmp(str1.c_str(), str2.c_str(), count);
			THREAD_LOG_INFO("_strnicmp('{}', '{}', {}) -> {}", str1, str2, count, r);
			return r;
		});

	// strncpy pads the destination out to `count` with nulls and does not
	// terminate when the source fills it exactly -- both of which a driver
	// relies on, and neither of which write_string_buffer does.
	state.redirect(mod, "strncpy",
		[](vcpu& cpu, const addr_t destination, std::string source,
			const std::uint64_t count) -> addr_t
		{
			std::string out(count, '\0');
			source.copy(out.data(), std::min<std::size_t>(count, source.size()));

			cpu.curr_addr_space()->write_mem(destination, out.data(), count);

			THREAD_LOG_INFO("strncpy(dest=0x{:X}, '{}', {})", destination, source, count);

			return destination;
		});

	state.redirect(mod, "wcsncpy",
		[](vcpu& cpu, const addr_t destination, std::wstring source,
			const std::uint64_t count) -> addr_t
		{
			std::wstring out(count, L'\0');
			source.copy(out.data(), std::min<std::size_t>(count, source.size()));

			cpu.curr_addr_space()->write_mem(destination, out.data(), count * sizeof(wchar_t));

			THREAD_LOG_INFO("wcsncpy(dest=0x{:X}, '{}', {})",
				destination, narrow_wstring(source), count);

			return destination;
		});

	// The result points into the guest's own copy of the haystack, so what the
	// host CRT found is turned back into an offset from the address the guest
	// passed in.
	state.redirect(mod, "strstr",
		[](vcpu& cpu, const addr_t str, std::string sub_str) -> addr_t
		{
			const auto haystack = guest::read_string(*cpu.curr_addr_space(), str);
			const auto pos = haystack.find(sub_str);

			const auto found = pos == std::string::npos ? 0 : str + pos;

			THREAD_LOG_INFO("strstr('{}', '{}') -> 0x{:X}", haystack, sub_str, found);

			return found;
		});

	state.redirect(mod, "wcscpy_s",
		[](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_words,
			std::wstring source) -> std::int32_t
		{
			if (!destination || !size_in_words)
				return crt_einval;

			if (source.size() + 1 > size_in_words)
			{
				// The _s routines empty the destination on a range failure so a
				// caller that ignores the result cannot read a partial copy.
				cpu.curr_addr_space()->write_mem<wchar_t>(destination, L'\0');
				return crt_erange;
			}

			guest::write_wstring_buffer(*cpu.curr_addr_space(), destination,
				size_in_words, source);

			THREAD_LOG_INFO("wcscpy_s(dest=0x{:X}, {}, '{}')",
				destination, size_in_words, narrow_wstring(source));

			return 0;
		});

	state.redirect(mod, "wcscat_s",
		[](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_words,
			std::wstring source) -> std::int32_t
		{
			if (!destination || !size_in_words)
				return crt_einval;

			auto& space = *cpu.curr_addr_space();
			const auto existing = guest::read_wstring(space, destination);

			if (existing.size() + source.size() + 1 > size_in_words)
			{
				space.write_mem<wchar_t>(destination, L'\0');
				return crt_erange;
			}

			guest::write_wstring_buffer(space, destination, size_in_words, existing + source);

			THREAD_LOG_INFO("wcscat_s(dest=0x{:X}, {}, '{}') -> '{}'", destination,
				size_in_words, narrow_wstring(source), narrow_wstring(existing + source));

			return 0;
		});

	// The character classifiers take and return an int so that EOF fits, which
	// is why these are not unsigned.
	state.redirect(mod, "tolower", [](vcpu&, const std::int32_t c) -> std::int32_t
	{
		THREAD_LOG_INFO("tolower({}) -> {}", c, std::tolower(c));
		return std::tolower(c);
	});

	state.redirect(mod, "towlower", [](vcpu&, const std::int32_t c) -> std::int32_t
	{
		THREAD_LOG_INFO("towlower({}) -> {}", c, std::towlower(static_cast<std::wint_t>(c)));
		return std::towlower(static_cast<std::wint_t>(c));
	});

	state.redirect(mod, "towupper", [](vcpu&, const std::int32_t c) -> std::int32_t
	{
		THREAD_LOG_INFO("towupper({}) -> {}", c, std::towupper(static_cast<std::wint_t>(c)));
		return std::towupper(static_cast<std::wint_t>(c));
	});

	// The four wide formatters. They differ only in where the arguments come
	// from and whether overflow truncates or is an error, so the formatting
	// itself is guest::vswprintf in every case.
	//
	// _snwprintf truncates and returns -1 when it does; the _s pair empty the
	// destination and return -1, which is what their constraint handler would
	// leave behind had one been installed.
	auto write_formatted = [](vcpu& cpu, const addr_t destination,
		const std::uint64_t count, const std::wstring& text, const bool secure) -> std::int32_t
	{
		auto& space = *cpu.curr_addr_space();

		if (!destination || !count)
			return -1;

		if (text.size() >= count)
		{
			if (secure)
			{
				space.write_mem<wchar_t>(destination, L'\0');
				return -1;
			}

			// Truncated, and deliberately not terminated: that is what the
			// non-secure form does when the text fills the buffer exactly.
			space.write_mem(destination, text.data(), count * sizeof(wchar_t));
			return -1;
		}

		guest::write_wstring_buffer(space, destination, count, text);

		THREAD_LOG_INFO("wide format(dest=0x{:X}, count={}) -> '{}'",
			destination, count, narrow_wstring(text));

		return static_cast<std::int32_t>(text.size());
	};

	state.redirect(mod, "_snwprintf",
		[write_formatted](vcpu& cpu, const addr_t destination, const std::uint64_t count,
			std::wstring format) -> std::int32_t
		{
			const auto text = guest::vswprintf(*cpu.curr_addr_space(), format, varargs(cpu, 3));
			return write_formatted(cpu, destination, count, text, false);
		});

	state.redirect(mod, "swprintf_s",
		[write_formatted](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_words,
			std::wstring format) -> std::int32_t
		{
			const auto text = guest::vswprintf(*cpu.curr_addr_space(), format, varargs(cpu, 3));
			return write_formatted(cpu, destination, size_in_words, text, true);
		});

	state.redirect(mod, "_vsnwprintf",
		[write_formatted](vcpu& cpu, const addr_t destination, const std::uint64_t count,
			std::wstring format, const addr_t arg_list) -> std::int32_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto text = guest::vswprintf(space, format, guest::va_list_args(space, arg_list));
			return write_formatted(cpu, destination, count, text, false);
		});

	state.redirect(mod, "vswprintf_s",
		[write_formatted](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_words,
			std::wstring format, const addr_t arg_list) -> std::int32_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto text = guest::vswprintf(space, format, guest::va_list_args(space, arg_list));
			return write_formatted(cpu, destination, size_in_words, text, true);
		});
}
