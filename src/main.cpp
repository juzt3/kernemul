#include "target.hpp"
#include "kernel/win/win_kernel.hpp"
#include "emu/calling_conv.hpp"
#include "util/log.hpp"

// The backend the guest runs on, picked at build time with KERNEMUL_BACKEND.
// Unicorn interprets; whp runs the guest on the host cpu in a Hyper-V
// partition, which is one cpu rather than four -- its hook and step state is
// per partition, so a second cpu stepping over a hooked access would unprotect
// the pages under the first.
#if defined(KERNEMUL_HAS_WHP)
	#include "emu/x86/whp.hpp"

	using guest_emu = x86_whp_emu;
	inline constexpr std::size_t vcpu_count = 1;
#else
	#include "emu/unicorn.hpp"

	using guest_emu = unicorn_emu;

	// Everything the guest is told about the machine agrees with this number:
	// the KUSER_SHARED_DATA count, the PEB, the affinity masks and the
	// topology SystemInformation classes are all filled in from it.
	inline constexpr std::size_t vcpu_count = 4;
#endif

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

// A driver: mapped into the system process and entered on a system thread.
static int run_driver(guest::win_emulator& win,
	const std::shared_ptr<guest::calling_conv>& conv, const std::string& name)
{
	auto& kernel = win.kernel();
	auto& proc = *kernel.sys_proc;

	auto driver = krnl::map_img(proc, std::string(target::guest_fs_dir) + name, true);

	if (!driver)
	{
		LOG_ERR("failed to map {}", name);
		return 1;
	}

	// What Windows hands a driver: the object it hangs everything it exposes
	// off, and the service key it was started from.
	auto args = kernel.create_driver(*driver, u"test_driver");

	win.create_vcpus(vcpu_count);

	auto cpu = win.cpus().front();

	// This thread drives that cpu until run_all hands it to one of its own, so
	// anything reached while the machine is still being built says where from.
	set_log_cpu(cpu.get());

	// DriverEntry runs as a system thread like any other, so the scheduler owns
	// its stack and the return address that says it is done.
	const auto entry = win.create_kernel_thread(*cpu, driver->entry_point);

	// DriverEntry(DriverObject, RegistryPath)
	conv->set_arg(*cpu, *entry, 0, args.driver_object.address());
	conv->set_arg(*cpu, *entry, 1, args.registry_path.address());

	win.run_all();

	LOG_INFO("driver returned, status=0x{:X}", conv->read_ret(*cpu, *entry));

	return 0;
}

// An application: its own process and address space, with a thread that starts
// inside ntdll's loader. The cpus come first here, unlike the driver path --
// building the process queues a thread, which needs a cpu to be built against.
static int run_user(guest::win_emulator& win, const std::string_view exe_name)
{
	win.create_vcpus(vcpu_count);

	auto cpu = win.cpus().front();
	set_log_cpu(cpu.get());

	const auto app = win.create_user_process(*cpu, exe_name);

	if (!app.thread)
	{
		LOG_ERR("failed to create a process for {}", exe_name);
		return 1;
	}

	win.run_all();

	LOG_INFO("{} finished", exe_name);

	return 0;
}

// A .sys goes down the driver path, anything else runs as an application. The
// name is looked up in the guest root for the architecture this was built for.
int main(const int argc, const char* const* const argv)
{
	LOG_INFO("kernemul targeting {}", target::name);

	const std::string image = argc > 1 ? argv[1] : "test_printf.exe";

	auto mem = std::make_shared<guest::mmu>();
	auto conv = std::make_shared<guest::calling_conv>();
	auto e = std::make_shared<guest_emu>(mem, conv);

	guest::win_emulator win(e);

	return image.ends_with(".sys")
		? run_driver(win, conv, image)
		: run_user(win, image);
}
