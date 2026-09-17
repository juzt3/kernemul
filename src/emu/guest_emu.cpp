#include "guest_emu.hpp"

// The one translation unit that sees a backend's headers, and so the one that may see <windows.h>.
#if defined(KERNEMUL_HAS_WHP)
	#include "x86/whp.hpp"

	using guest_emu_impl = x86_whp_emu;
#else
	#include "unicorn.hpp"

	using guest_emu_impl = unicorn_emu;
#endif

std::shared_ptr<emu> make_guest_emu(std::shared_ptr<mmu> mem, std::shared_ptr<calling_conv> conv)
{
	return std::make_shared<guest_emu_impl>(std::move(mem), std::move(conv));
}
