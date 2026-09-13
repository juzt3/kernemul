#include "nt_string_ops.hpp"
#include "../win_kernel.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"

// All five are pure functions over guest memory: there is no state to keep and
// nothing to fake, so they are implemented rather than accounted for.
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
}
