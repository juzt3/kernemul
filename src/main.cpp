#include "kernel/win/win_kernel.hpp"
#include "emu/unicorn.hpp"
#include "emu/calling_conv.hpp"
#include "emu/x86/mmu.hpp"
#include "emu/x86/arch.hpp"
#include "util/log.hpp"
int main()
{
	auto arch = std::make_shared<x86::arch>();
	auto mem = std::make_shared<x86::mmu>();
	auto conv = std::make_shared<x86_win_conv>();
	auto e = std::make_shared<unicorn_emu>(arch, mem, conv);

	windows_emulator win(e);

	LOG_INFO("windows emulator initialized");

	auto& kernel = win.kernel();
	auto& proc = *kernel.sys_proc;

	auto driver = krnl::map_img(proc, "fs/test_driver.sys", true);

	if (!driver)
	{
		LOG_ERR("failed to map test driver");
		return 1;
	}

	LOG_INFO("driver mapped at 0x{:X}, entry=0x{:X}", driver->addr, driver->entry_point);

	auto cpu = e->add_vcpu();
	auto space = cpu->curr_addr_space();

	constexpr std::size_t stack_size = 0x10000;
	const addr_t stack_base = space->alloc(stack_size, prot_rw | prot_supervisor);
	cpu->set_sp(stack_base + stack_size - 0x100);

	const addr_t sentinel_page = space->alloc(0x1000, prot_rx | prot_supervisor);

	e->hook_code(sentinel_page, sentinel_page + 0xFFF,
		[](vcpu& cpu, addr_t, std::size_t) { cpu.stop(); });

	auto rsp = cpu->sp();
	rsp -= 8;
	space->write_mem(rsp, sentinel_page);
	cpu->set_sp(rsp);

	cpu->reg(x86::rcx, addr_t{0});
	cpu->reg(x86::rdx, addr_t{0});

	cpu->set_pc(driver->entry_point);

	LOG_INFO("running driver at 0x{:X}", driver->entry_point);
	cpu->run();
	LOG_INFO("driver returned");

	return 0;
}
