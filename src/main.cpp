#include "kernel/win/win_kernel.hpp"
#include "emu/unicorn.hpp"
#include "emu/calling_conv.hpp"
#include "emu/x86/mmu.hpp"
#include "util/log.hpp"

int main()
{
	auto arch = std::make_shared<x86::arch>();
	auto mem = std::make_shared<x86::mmu>();
	auto conv = std::make_shared<x86_win_conv>();
	auto e = std::make_shared<unicorn_emu>(arch, mem, conv);

	windows_emulator win(e);

	LOG_INFO("windows emulator initialized");
}
