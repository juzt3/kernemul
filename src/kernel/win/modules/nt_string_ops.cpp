#include "nt_string_ops.hpp"
#include "../win_kernel.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <algorithm>
#include <cstring>
#include <vector>

// All of these are pure functions over guest memory: there is no state to keep
// and nothing to fake, so they are implemented rather than accounted for.
void modules::register_ntoskrnl_string_ops(win_kernel_state& state, proc_module& mod)
{
	state.redirect(mod, "RtlInitUnicodeString",
		[](vcpu& cpu, emu_object<_UNICODE_STRING> destination, const addr_t source)
		{
			if (!destination)
				return;

			auto& space = *cpu.curr_addr_space();

			_UNICODE_STRING out{};
			out.Buffer = guest_ptr<wchar_t>(source);

			if (source)
			{
				const auto s = guest::read_wstring(space, source);
				out.Length = static_cast<unsigned short>(s.size() * sizeof(wchar_t));
				out.MaximumLength = static_cast<unsigned short>(out.Length + sizeof(wchar_t));
			}

			destination.write(out);

			THREAD_LOG_INFO("RtlInitUnicodeString(dest=0x{:X}, src=0x{:X}): len={}",
				destination.address(), source, out.Length);
		});

	state.redirect(mod, "RtlInitAnsiString",
		[](vcpu& cpu, emu_object<_STRING> destination, const addr_t source)
		{
			if (!destination)
				return;

			auto& space = *cpu.curr_addr_space();

			_STRING out{};
			out.Buffer = guest_ptr<char>(source);

			if (source)
			{
				const auto s = guest::read_string(space, source);
				out.Length = static_cast<unsigned short>(s.size());
				out.MaximumLength = static_cast<unsigned short>(out.Length + 1);
			}

			destination.write(out);

			THREAD_LOG_INFO("RtlInitAnsiString(dest=0x{:X}, src=0x{:X}): len={}",
				destination.address(), source, out.Length);
		});

	state.redirect(mod, "RtlCompareUnicodeString",
		[](vcpu&, emu_object<_UNICODE_STRING> string1, emu_object<_UNICODE_STRING> string2,
			const std::uint8_t case_insensitive) -> std::int32_t
		{
			const auto a = win::read_unicode_string(string1);
			const auto b = win::read_unicode_string(string2);
			const auto r = win::compare_unicode(a, b, case_insensitive != 0);

			THREAD_LOG_INFO("RtlCompareUnicodeString('{}', '{}', ci={}) -> {}",
				narrow_wstring(a), narrow_wstring(b), case_insensitive, r);

			return r;
		});

	state.redirect(mod, "RtlEqualUnicodeString",
		[](vcpu&, emu_object<_UNICODE_STRING> string1, emu_object<_UNICODE_STRING> string2,
			const std::uint8_t case_insensitive) -> bool
		{
			const auto a = win::read_unicode_string(string1);
			const auto b = win::read_unicode_string(string2);
			const bool eq = a.size() == b.size()
				&& win::compare_unicode(a, b, case_insensitive != 0) == 0;

			THREAD_LOG_INFO("RtlEqualUnicodeString('{}', '{}', ci={}) -> {}",
				narrow_wstring(a), narrow_wstring(b), case_insensitive, eq);

			return eq;
		});

	state.redirect(mod, "RtlPrefixUnicodeString",
		[](vcpu&, emu_object<_UNICODE_STRING> prefix, emu_object<_UNICODE_STRING> string,
			const std::uint8_t case_insensitive) -> bool
		{
			const auto a = win::read_unicode_string(prefix);
			const auto b = win::read_unicode_string(string);

			const bool is_prefix = a.size() <= b.size()
				&& win::compare_unicode(a, std::wstring_view(b).substr(0, a.size()),
					case_insensitive != 0) == 0;

			THREAD_LOG_INFO("RtlPrefixUnicodeString('{}', '{}', ci={}) -> {}",
				narrow_wstring(a), narrow_wstring(b), case_insensitive, is_prefix);

			return is_prefix;
		});

	state.redirect(mod, "RtlCompareString",
		[](vcpu&, emu_object<_STRING> string1, emu_object<_STRING> string2,
			const std::uint8_t case_insensitive) -> std::int32_t
		{
			const auto a = win::read_ansi_string(string1);
			const auto b = win::read_ansi_string(string2);

			const auto r = case_insensitive
				? _strnicmp(a.c_str(), b.c_str(), std::min(a.size(), b.size()))
				: a.compare(b);

			// A shared prefix leaves the shorter string the lesser, which the
			// folded compare above cannot say on its own.
			const auto result = (r != 0)
				? r
				: static_cast<std::int32_t>(a.size()) - static_cast<std::int32_t>(b.size());

			THREAD_LOG_INFO("RtlCompareString('{}', '{}', ci={}) -> {}",
				a, b, case_insensitive, result);

			return result;
		});

	state.redirect(mod, "RtlCompareMemory",
		[](vcpu& cpu, const addr_t source1, const addr_t source2,
			const std::uint64_t length) -> std::uint64_t
		{
			auto& space = *cpu.curr_addr_space();

			std::vector<std::uint8_t> a(length), b(length);
			space.read_mem(source1, a.data(), length);
			space.read_mem(source2, b.data(), length);

			// How many leading bytes match, which is `length` when they are
			// equal -- not memcmp's sign.
			const auto matched = static_cast<std::uint64_t>(
				std::mismatch(a.begin(), a.end(), b.begin()).first - a.begin());

			THREAD_LOG_INFO("RtlCompareMemory(0x{:X}, 0x{:X}, {}) -> {}",
				source1, source2, length, matched);

			return matched;
		});

	// The two code-page conversions. Both are ascii here: a real conversion
	// goes through the system code page, and nothing in the emulator sets one
	// up, so anything above 0x7F is carried across unchanged rather than
	// mapped. The sizes and statuses are the real ones either way, which is
	// what a caller sizing a buffer actually depends on.
	state.redirect(mod, "RtlMultiByteToUnicodeN",
		[](vcpu& cpu, const addr_t unicode_string, const std::uint32_t max_bytes_in_unicode_string,
			emu_object<std::uint32_t> bytes_in_unicode_string, const addr_t multi_byte_string,
			const std::uint32_t bytes_in_multi_byte_string) -> NTSTATUS
		{
			auto& space = *cpu.curr_addr_space();

			std::string narrow(bytes_in_multi_byte_string, '\0');

			if (bytes_in_multi_byte_string)
				space.read_mem(multi_byte_string, narrow.data(), bytes_in_multi_byte_string);

			const auto chars = std::min<std::size_t>(narrow.size(),
				max_bytes_in_unicode_string / sizeof(wchar_t));
			const auto wide = widen_string(std::string_view(narrow).substr(0, chars));

			if (bytes_in_unicode_string)
				bytes_in_unicode_string.write(static_cast<std::uint32_t>(wide.size() * sizeof(wchar_t)));

			if (unicode_string && !wide.empty())
				space.write_mem(unicode_string, wide.data(), wide.size() * sizeof(wchar_t));

			THREAD_LOG_INFO("RtlMultiByteToUnicodeN(in={} bytes, out={} bytes) -> '{}'",
				bytes_in_multi_byte_string, wide.size() * sizeof(wchar_t), narrow_wstring(wide));

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "RtlUnicodeToUTF8N",
		[](vcpu& cpu, const addr_t utf8_string_destination, const std::uint32_t utf8_string_max_byte_count,
			emu_object<std::uint32_t> utf8_string_actual_byte_count, const addr_t unicode_string_source,
			const std::uint32_t unicode_string_byte_count) -> NTSTATUS
		{
			auto& space = *cpu.curr_addr_space();

			std::wstring wide(unicode_string_byte_count / sizeof(wchar_t), L'\0');

			if (unicode_string_byte_count)
				space.read_mem(unicode_string_source, wide.data(), unicode_string_byte_count);

			const auto narrow = narrow_wstring(wide);
			const auto written = std::min<std::size_t>(narrow.size(), utf8_string_max_byte_count);

			if (utf8_string_actual_byte_count)
				utf8_string_actual_byte_count.write(static_cast<std::uint32_t>(written));

			if (utf8_string_destination && written)
				space.write_mem(utf8_string_destination, narrow.data(), written);

			THREAD_LOG_INFO("RtlUnicodeToUTF8N(in={} bytes, out={} bytes) -> '{}'",
				unicode_string_byte_count, written, narrow.substr(0, written));

			// The real one says so when the destination could not take it all,
			// and a caller sizing a buffer loops on exactly this.
			return written < narrow.size() ? STATUS_BUFFER_TOO_SMALL : STATUS_SUCCESS;
		});

	// RtlGetDefaultCodePage(PUSHORT AnsiCodePage, PUSHORT OemCodePage). Nothing
	// here installs a code page, so these name the Windows defaults -- 1252 and
	// 437 -- which is what the ascii-only conversions above behave as.
	state.redirect(mod, "RtlGetDefaultCodePage",
		[](vcpu&, emu_object<std::uint16_t> ansi_code_page,
			emu_object<std::uint16_t> oem_code_page)
		{
			constexpr std::uint16_t ansi_latin1 = 1252;
			constexpr std::uint16_t oem_us = 437;

			if (ansi_code_page)
				ansi_code_page.write(ansi_latin1);

			if (oem_code_page)
				oem_code_page.write(oem_us);

			THREAD_LOG_INFO("RtlGetDefaultCodePage() -> ansi={}, oem={}", ansi_latin1, oem_us);
		});
}
