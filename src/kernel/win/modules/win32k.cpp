#include "win32k.hpp"
#include "../types.hpp"
#include "../win_kernel.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"

// No desktop, so the message goes to the log and the caller is told the user
// pressed the default button.
void modules::register_win32k(win_kernel_state& state, proc_module& mod)
{
	state.redirect(mod, "NtUserMessageCall",
		[](vcpu& cpu, const std::uint64_t window, const addr_t text,
			const addr_t caption, const std::uint32_t type) -> std::uint64_t
		{
			auto& space = *cpu.curr_addr_space();

			const auto message = text ? narrow_wstring(guest::read_wstring(space, text)) : "";
			const auto title = caption ? narrow_wstring(guest::read_wstring(space, caption)) : "";

			THREAD_LOG_WARN("NtUserMessageCall(window=0x{:X}, type=0x{:X}): '{}' / '{}'",
				window, type, title, message);

			return 1;
		});
}
