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

	constexpr std::size_t vcpu_count = 4;
	win.create_vcpus(vcpu_count);

	auto cpu = win.cpus().front();

	// DriverEntry runs as a system thread like any other, so the scheduler owns
	// its stack and the return address that says it is done.
	const auto entry = win.create_kernel_thread(*cpu, driver->entry_point);

	// DriverEntry(DriverObject, RegistryPath)
	conv->set_arg(*cpu, *entry, 0, 0);
	conv->set_arg(*cpu, *entry, 1, 0);

	win.run_all();

	LOG_INFO("driver returned, status=0x{:X}", conv->read_ret(*cpu, *entry));

	return 0;
}
