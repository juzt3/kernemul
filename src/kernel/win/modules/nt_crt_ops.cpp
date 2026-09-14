#include "nt_crt_ops.hpp"
#include "../win_kernel.hpp"
#include "../../../emu/guest_call.hpp"
#include "../../../util/format.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <numeric>
#include <vector>

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
	auto* st = &state;

	state.redirect(mod, "wcslen", [](vcpu&, std::u16string str) -> std::uint64_t
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
			const auto r = compare_ascii_nocase<char>(str1, str2);
			THREAD_LOG_INFO("_stricmp('{}', '{}') -> {}", str1, str2, r);
			return r;
		});

	state.redirect(mod, "_strnicmp",
		[](vcpu&, std::string str1, std::string str2, const std::uint64_t count) -> std::int32_t
		{
			const auto r = compare_ascii_nocase(str1.c_str(), str2.c_str(),
				std::min<std::size_t>(count, std::min(str1.size(), str2.size()) + 1));
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
		[](vcpu& cpu, const addr_t destination, std::u16string source,
			const std::uint64_t count) -> addr_t
		{
			std::u16string out(count, u'\0');
			source.copy(out.data(), std::min<std::size_t>(count, source.size()));

			cpu.curr_addr_space()->write_mem(destination, out.data(), count * sizeof(char16_t));

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
			std::u16string source) -> std::int32_t
		{
			if (!destination || !size_in_words)
				return crt_einval;

			if (source.size() + 1 > size_in_words)
			{
				// The _s routines empty the destination on a range failure so a
				// caller that ignores the result cannot read a partial copy.
				cpu.curr_addr_space()->write_mem<char16_t>(destination, u'\0');
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
			std::u16string source) -> std::int32_t
		{
			if (!destination || !size_in_words)
				return crt_einval;

			auto& space = *cpu.curr_addr_space();
			const auto existing = guest::read_wstring(space, destination);

			if (existing.size() + source.size() + 1 > size_in_words)
			{
				space.write_mem<char16_t>(destination, u'\0');
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
		const std::uint64_t count, const std::u16string& text, const bool secure) -> std::int32_t
	{
		auto& space = *cpu.curr_addr_space();

		if (!destination || !count)
			return -1;

		if (text.size() >= count)
		{
			if (secure)
			{
				space.write_mem<char16_t>(destination, u'\0');
				return -1;
			}

			// Truncated, and deliberately not terminated: that is what the
			// non-secure form does when the text fills the buffer exactly.
			space.write_mem(destination, text.data(), count * sizeof(char16_t));
			return -1;
		}

		guest::write_wstring_buffer(space, destination, count, text);

		THREAD_LOG_INFO("wide format(dest=0x{:X}, count={}) -> '{}'",
			destination, count, narrow_wstring(text));

		return static_cast<std::int32_t>(text.size());
	};

	state.redirect(mod, "_snwprintf",
		[write_formatted](vcpu& cpu, const addr_t destination, const std::uint64_t count,
			std::u16string format) -> std::int32_t
		{
			const auto text = guest::vswprintf(*cpu.curr_addr_space(), format, varargs(cpu, 3));
			return write_formatted(cpu, destination, count, text, false);
		});

	state.redirect(mod, "swprintf_s",
		[write_formatted](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_words,
			std::u16string format) -> std::int32_t
		{
			const auto text = guest::vswprintf(*cpu.curr_addr_space(), format, varargs(cpu, 3));
			return write_formatted(cpu, destination, size_in_words, text, true);
		});

	state.redirect(mod, "_vsnwprintf",
		[write_formatted](vcpu& cpu, const addr_t destination, const std::uint64_t count,
			std::u16string format, const addr_t arg_list) -> std::int32_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto text = guest::vswprintf(space, format, guest::va_list_args(space, arg_list));
			return write_formatted(cpu, destination, count, text, false);
		});

	state.redirect(mod, "vswprintf_s",
		[write_formatted](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_words,
			std::u16string format, const addr_t arg_list) -> std::int32_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto text = guest::vswprintf(space, format, guest::va_list_args(space, arg_list));
			return write_formatted(cpu, destination, size_in_words, text, true);
		});

	// The counted _s pair. They take a maximum character count as well as the
	// buffer size, and _TRUNCATE in that slot is what asks for the truncation
	// the plain _s forms above refuse to do.
	auto write_counted = [](addr_space& space, const addr_t destination, const std::uint64_t count,
		const std::uint64_t max_count, const auto& text) -> std::int32_t
	{
		constexpr auto truncate = ~std::uint64_t{0};

		if (!destination || !count)
			return crt_einval;

		const auto wanted = max_count == truncate
			? text.size()
			: std::min<std::size_t>(text.size(), max_count);

		if (wanted + 1 <= count)
		{
			guest::write_basic_string_buffer(space, destination, count,
				std::basic_string_view(text).substr(0, wanted));

			return static_cast<std::int32_t>(wanted);
		}

		// Too long for the buffer: _TRUNCATE said to keep what fits, and
		// anything else empties the destination as the other _s routines do.
		const auto kept = max_count == truncate ? count - 1 : 0;

		guest::write_basic_string_buffer(space, destination, count,
			std::basic_string_view(text).substr(0, kept));

		return -1;
	};

	state.redirect(mod, "_vsnprintf_s",
		[write_counted](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_bytes,
			const std::uint64_t max_count, std::string format, const addr_t arg_list) -> std::int32_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto text = guest::vsprintf(space, format, guest::va_list_args(space, arg_list));
			const auto written = write_counted(space, destination, size_in_bytes, max_count, text);

			THREAD_LOG_INFO("_vsnprintf_s(dest=0x{:X}, {}, {}) -> '{}' ({})",
				destination, size_in_bytes, max_count, text, written);

			return written;
		});

	state.redirect(mod, "_vsnwprintf_s",
		[write_counted](vcpu& cpu, const addr_t destination, const std::uint64_t size_in_words,
			const std::uint64_t max_count, std::u16string format, const addr_t arg_list) -> std::int32_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto text = guest::vswprintf(space, format, guest::va_list_args(space, arg_list));
			const auto written = write_counted(space, destination, size_in_words, max_count, text);

			THREAD_LOG_INFO("_vsnwprintf_s(dest=0x{:X}, {}, {}) -> '{}' ({})",
				destination, size_in_words, max_count, narrow_wstring(text), written);

			return written;
		});

	// Sorted over indices, so the array the guest comparator reads does not move
	// until the write back. A merge sort because std::sort answers a comparator
	// that is not a strict weak ordering by running off the end of the array.
	state.redirect(mod, "qsort",
		[st](vcpu& cpu, const addr_t base, const std::uint64_t count,
			const std::uint64_t width, const addr_t comparator)
		{
			THREAD_LOG_INFO("qsort(base=0x{:X}, count={}, width={}, comparator=0x{:X})",
				base, count, width, comparator);

			if (!base || !width || !comparator || count < 2)
				return;

			auto& space = *cpu.curr_addr_space();

			std::vector<std::uint8_t> elements(count * width);
			space.read_mem(base, elements.data(), elements.size());

			std::vector<std::size_t> order(count);
			std::iota(order.begin(), order.end(), 0);

			std::stable_sort(order.begin(), order.end(),
				[&](const std::size_t a, const std::size_t b)
				{
					const std::uint64_t args[] = { base + a * width, base + b * width };

					return static_cast<std::int32_t>(
						st->calls.call(cpu, comparator, args)) < 0;
				});

			std::vector<std::uint8_t> sorted(elements.size());

			for (std::size_t i = 0; i < count; ++i)
				std::memcpy(sorted.data() + i * width,
					elements.data() + order[i] * width, width);

			space.write_mem(base, sorted.data(), sorted.size());

			THREAD_LOG_INFO("qsort: {} elements sorted", count);
		});
}
