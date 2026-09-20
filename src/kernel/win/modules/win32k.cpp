#include "win32k.hpp"
#include "../types.hpp"
#include "../win_kernel.hpp"
#include "../../../util/log.hpp"

// There is no desktop and no window, so the message is logged and reported as handled.
void modules::register_win32k(win_kernel_state& state, proc_module& mod)
{
	state.redirect(mod, "NtUserMessageCall",
		[](vcpu&, const addr_t window, const std::uint32_t message,
			const std::uint64_t wparam, const std::uint64_t lparam,
			const addr_t result_info, const std::uint32_t type,
			const bool ansi) -> std::uint64_t
		{
			THREAD_LOG_WARN("NtUserMessageCall(window=0x{:X}, message=0x{:X}, wparam=0x{:X}, "
				"lparam=0x{:X}, result=0x{:X}, type=0x{:X}, ansi={}): there is no window to "
				"send it to", window, message, wparam, lparam, result_info, type, ansi);

			return 1;
		});
}
