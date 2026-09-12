#include "target.hpp"
#include "kernel/win/win_kernel.hpp"
#include "emu/calling_conv.hpp"
#include "util/log.hpp"

#include "emu/unicorn.hpp"

#if defined(KERNEMUL_ARCH_ARM64)
	#include "kernel/win/arm64_win.hpp"
	#include "emu/arm64/mmu.hpp"
	#include "emu/arm64/calling_conv.hpp"

	namespace guest
	{
		using mmu          = arm64::mmu;
		using calling_conv = arm64_win_conv;
		using win_emulator = arm64_win_emulator;
	}
#else
	#include "kernel/win/x86_win.hpp"
	#include "emu/x86/mmu.hpp"
	#include "emu/x86/calling_conv.hpp"

	namespace guest
	{
		using mmu          = x86::mmu;
		using calling_conv = x86_win_conv;
		using win_emulator = x86_win_emulator;
	}
#endif

int main()
{
	LOG_INFO("kernemul targeting {}", target::name);

	auto mem = std::make_shared<guest::mmu>();
	auto conv = std::make_shared<guest::calling_conv>();
	auto e = std::make_shared<unicorn_emu>(mem, conv);

	guest::win_emulator win(e);

	auto& kernel = win.kernel();
	auto& proc = *kernel.sys_proc;

	auto driver = krnl::map_img(proc, std::string(target::guest_fs_dir) + "test_driver.sys", true);

	if (!driver)
	{
		LOG_ERR("failed to map test driver");
		return 1;
	}

	auto cpu = win.add_vcpu();
	auto space = cpu->curr_addr_space();

	constexpr std::size_t stack_size = 0x10000;
	const addr_t stack_base = space->alloc(stack_size, prot_rw | prot_supervisor);
	cpu->set_sp(stack_base + stack_size - 0x100);

	const addr_t sentinel_page = space->alloc(0x1000, prot_rx | prot_supervisor);

	e->hook_code(sentinel_page, sentinel_page + 0xFFF,
		[](vcpu& cpu, addr_t, std::size_t) { cpu.stop(); });

	// Hand DriverEntry a return address the emulator can catch. On x86 that
	// means pushing it; on AArch64 it goes in the link register.
	e->arch()->set_ret_addr(*cpu, sentinel_page);

	// DriverEntry(DriverObject, RegistryPath)
	conv->write_arg(*cpu, 0, 0);
	conv->write_arg(*cpu, 1, 0);

	cpu->set_pc(driver->entry_point);

	cpu->run();

	LOG_INFO("driver returned, status=0x{:X}", conv->read_ret(*cpu));

	return 0;
}
