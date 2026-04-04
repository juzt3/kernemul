#include "emulator/backend/hypermulator_backend.hpp"
#include "emulator/backend/unicorn_backend.hpp"
#include "emulator/object.hpp"
#include "kernel/kernel.hpp"
#include "kernel/kernel_string.hpp"
#include "kernel/exception.hpp"
#include "kernel/image_loader.hpp"
#include "kernel/process_loader.hpp"
#include "kernel/segments.hpp"
#include "config.hpp"

#include <ia32-doc/ia32.hpp>
#include "util/logs.hpp"
#include "util/util.hpp"

#include "portable_executable/dos_header.hpp"
#include "portable_executable/image.hpp"

static void set_up_user_shared_data(const std::shared_ptr<emulator_t>& emulator)
{
	_KUSER_SHARED_DATA contents = { };

	contents.NtBuildNumber = 19045;
	contents.NtMajorVersion = 10;
	contents.NtMinorVersion = 0;

	kernel::user_shared_data = emulator_object_t<_KUSER_SHARED_DATA>::allocate_at(emulator, contents, 0xFFFFF78000000000);
}

static emulator_object_t<_DRIVER_OBJECT> set_up_driver_object(const std::shared_ptr<emulator_t>& emulator, const kernel_image_t& image)
{
	_DRIVER_OBJECT contents = { };

	const auto& table_entry = image.table_entry();

	contents.DriverSection = reinterpret_cast<void*>(table_entry.address());
	contents.DriverStart = reinterpret_cast<void*>(image.base_address());
	contents.DriverSize = static_cast<std::uint32_t>(image.size());

	return emulator_object_t<_DRIVER_OBJECT>::allocate(emulator, contents, image.name());
}

static void set_up_driver_entry(const std::shared_ptr<emulator_t>& emulator)
{
	const auto driver_object = set_up_driver_object(emulator, *kernel::emulated_module);
	const auto registry_path = kernel::allocate_unicode_string_object(emulator, EMULATED_MODULE_REG_PATH, "RegistryPath");

	emulator->write_register<x86::reg::rcx>(driver_object.address());
	emulator->write_register<x86::reg::rdx>(registry_path.address());
}

static void set_up_stack(emulator_t& emulator)
{
	constexpr emulator_t::size_type stack_size = 0x10000;

	const auto stack_base_address = emulator.heap_allocate(stack_size, prot_read_write);

	emulator_err_t error = stack_base_address.error_or({});

	error.throw_if("map stack");

	const emulator_t::address_type starting_rsp_value = *stack_base_address + stack_size - 0x1000 - 8;

	emulator.write_register<x86::reg::rsp>(starting_rsp_value);

	error = emulator.write_virtual_memory(starting_rsp_value, &emulator_t::thread_return_address, sizeof(emulator_t::thread_return_address));

	error.throw_if("set return address");
}

static emulator_object_t<_KPRCB> set_up_kprcb(const std::shared_ptr<emulator_t>& emulator,
                                              const std::shared_ptr<thread_t>& thread)
{
	_KPRCB contents;

	contents.CurrentThread = reinterpret_cast<_KTHREAD*>(thread->address());

	return emulator_object_t<_KPRCB>::allocate(emulator, contents);
}

static emulator_object_t<_KPCR> set_up_kpcr(const std::shared_ptr<emulator_t>& emulator,
                                            const std::shared_ptr<thread_t>& thread)
{
	const auto kprcb = set_up_kprcb(emulator, thread);

	auto kpcr = emulator_object_t<_KPCR>::allocate(emulator);

	_KPCR contents = { };

	contents.Self = reinterpret_cast<_KPCR*>(kpcr.address());
	contents.CurrentPrcb = reinterpret_cast<_KPRCB*>(kprcb.address());

	kpcr.write(contents);

	return kpcr;
}

static void patch_dbgctl_check(const std::shared_ptr<emulator_t>& emulator)
{
	const auto image_buffer = kernel::emulated_module->buffer();
	const auto image = reinterpret_cast<const portable_executable::image_t*>(image_buffer.data());

	if (const auto dbgctl_signature = image->signature_scan("0F 30 0F 32"))
	{
		const std::int64_t dbgctl_rva = dbgctl_signature - image_buffer.data();
		const emulator_t::address_type dbgctl_runtime_address = kernel::emulated_module->base_address() + dbgctl_rva;

		constexpr std::array<std::uint8_t, 4> stub = {
			0x31, 0xD2, // xor edx, edx
			0xB0, 0x03 // mov al, 3
		};

		const emulator_err_t error = emulator->write_virtual_memory(dbgctl_runtime_address, stub);

		error.throw_if("write MSR stub memory");
	}
}

static void set_up_lstar_msr(const std::shared_ptr<emulator_t>& emulator, const std::shared_ptr<kernel_image_t>& nt_image)
{
	if (const auto ki_system_call = nt_image->find_symbol("KiSystemCall64"))
	{
		const emulator_err_t error = emulator->write_msr(x86::msr::lstar, *ki_system_call);
		error.throw_if("write LSTAR MSR");
	}
}

static void set_up_interrupt_flag(const std::shared_ptr<emulator_t>& emulator)
{
	rflags flags = { .flags = emulator->read_register<x86::reg::rflags, std::uint64_t>() };

	flags.interrupt_enable_flag = 1;

	emulator->write_register<x86::reg::rflags>(flags.flags);
}

static void run_main_module(const std::shared_ptr<emulator_t>& emulator, const emulator_t::address_type entry_point_address)
{
	std::atomic_bool ended = false;

	auto thread_scheduler = std::thread(
		[&ended, emulator]()
		{
			while (!ended)
			{
				if (!kernel::pending_thread_switch)
				{
					kernel::switch_thread(emulator);
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(15));
			}
		}
	);

	emulator->write_register<x86::reg::rip>(entry_point_address);

	kernel::current_thread->save_state();

	std::shared_ptr<thread_t> last_thread;

	do
	{
		if (kernel::pending_thread_switch)
		{
			const auto next_thread = kernel::pending_threads.front();

			kernel::pending_threads.pop();

			if (!kernel::delete_current_thread)
			{
				kernel::pending_threads.push(kernel::current_thread);
			}

			kernel::current_thread = next_thread;

			kernel::delete_current_thread = false;
		}

		GLOBAL_LOG("running thread {}", kernel::current_thread->id());

		if (last_thread)
		{
			last_thread->save_state();
		}

		last_thread = kernel::current_thread;

		kernel::pending_thread_switch = false;
		kernel::current_thread->start();

	} while (kernel::pending_thread_switch);

	ended = true;

	thread_scheduler.join();
}

std::int32_t main()
{
	try
	{
		const auto emulator = std::static_pointer_cast<emulator_t>(std::make_shared<hypermulator_t>());

		kernel::filesystem = std::make_shared<filesystem_t>();
		kernel::registry = std::make_shared<registry_t>();
		kernel::object_manager = std::make_shared<object_manager_t>(emulator);

		const auto module_reg_key = kernel::registry->create_key(
			registry_t::normalize_path(EMULATED_MODULE_REG_PATH));
		module_reg_key->set_dword("Start", 1);
		module_reg_key->set_dword("Type", 1);
		module_reg_key->set_string("ImagePath",
			std::wstring(EMULATED_MODULE_DIRECTORY) + util::widen_string(EMULATED_MODULE_NAME));

		kernel::filesystem->load_at("ntoskrnl.exe", "system32/ntoskrnl.exe");
		kernel::filesystem->load_at("ntdll.dll", "system32/ntdll.dll");
		kernel::filesystem->load_at("win32k.sys", "system32/win32k.sys");

		kernel::filesystem->create_at("physicaldrive0");
		kernel::filesystem->create_at("physicaldrive1");
		kernel::filesystem->create_at("physicaldrive2");
		kernel::filesystem->create_at("physicaldrive3");
		kernel::filesystem->create_at("physicaldrive4");

		set_up_stack(*emulator);
		set_up_user_shared_data(emulator);

		// todo: check load order of these drivers
		const auto nt_image = kernel::map_kernel_image(emulator, "ntoskrnl.exe", false);
		kernel::map_kernel_image(emulator, "HAL.dll", false);
		kernel::map_kernel_image(emulator, "CI.dll", false);
		kernel::map_kernel_image(emulator, "kd.dll", false);
		kernel::map_kernel_image(emulator, "cng.sys", false, L"\\SystemRoot\\System32\\drivers\\");
		kernel::map_kernel_image(emulator, "FLTMGR.SYS", false, L"\\SystemRoot\\System32\\drivers\\");

		kernel::emulated_module = kernel::map_kernel_image(emulator, EMULATED_MODULE_NAME, true, EMULATED_MODULE_DIRECTORY);

		patch_dbgctl_check(emulator);
		set_up_interrupt_flag(emulator);
		
		kernel::set_up_initial_system_process(emulator);

		const auto current_thread_id = kernel::object_manager->allocate_id();

		const auto& system_process = kernel::process_entries.front();
		kernel::current_thread = kernel::create_thread(emulator, current_thread_id, system_process);

		kernel::set_up_gdt(emulator);
		kernel::set_up_segments(emulator);
		kernel::set_up_idt(emulator, *nt_image);

		const auto kpcr = set_up_kpcr(emulator, kernel::current_thread);
		kernel::set_up_kernel_gs(emulator, kpcr.address());

		set_up_lstar_msr(emulator, nt_image);

	    const emulator_t::address_type base_address = kernel::emulated_module->base_address();
		const emulator_t::address_type entry_point_address = kernel::emulated_module->entry_point();

		GLOBAL_LOG("mapped ntoskrnl at 0x{:X}", nt_image->base_address());
		GLOBAL_LOG("mapped image at 0x{:X}", base_address);

		const auto redirect_execute_handler = [emulator]
		([[maybe_unused]] const emulator_t::address_type accessed_address, [[maybe_unused]] const protection_t protection) -> void
		{
			const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type return_address = 0;

			const emulator_err_t read_error = emulator->read_virtual_memory(rsp, &return_address, sizeof(return_address));

			read_error.throw_if("read from stack");

			if (const auto redirected_function = kernel::find_redirected_function(rip))
			{
				THREAD_LOG("redirecting function (return address=0x{:X})", return_address);

				bool skip_return = false;

				(*redirected_function)(skip_return);

				if (!skip_return)
				{
					emulator->write_register<x86::reg::rsp>(rsp + 8);
					emulator->write_register<x86::reg::rip>(return_address);
				}

				return;
			}

			const auto module = kernel::find_module_from_rip(rip);

			std::string symbol_name;

			if (module)
			{
				if (const auto symbol = module->find_symbol_by_address(rip))
				{
					if (symbol->second == rip)
					{
						symbol_name = symbol->first;
					}
				}
			}

			if (!symbol_name.empty())
			{
				const auto module_name = module ? module->name() : "unknown";
				THREAD_ERR_LOG("unimplemented function '{}!{}' (address=0x{:X}, return address=0x{:X})", module_name, symbol_name, rip, return_address);
			}
			else
			{
				const auto module_name = module ? module->name() : "unknown";
				THREAD_ERR_LOG("unimplemented function in '{}' (address=0x{:X}, return address=0x{:X})", module_name, rip, return_address);
			}

			emulator->write_register<x86::reg::rip, emulator_t::address_type>(-1);

			emulator->stop();
		};

		for (const auto& module : kernel::module_entries)
		{
			if (module == kernel::emulated_module)
			{
				continue;
			}

			const emulator_err_t error = emulator->hook_memory(
				redirect_execute_handler,
				prot_execute,
				module->base_address(),
				module->base_address() + module->size()
			).error_or({});

			error.throw_if("monitor execute");
		}

		emulator_err_t error = emulator->hook_instruction(x86::insn::cpuid,
			[emulator]()
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
				const auto rax = emulator->read_register<x86::reg::rax, std::int32_t>();

				THREAD_LOG("cpuid executed at 0x{:X} (rax=0x{:X})", rip, rax);

				std::array<std::int32_t, 4> result;

				__cpuid(result.data(), rax);

				emulator->write_register<x86::reg::rax, std::int32_t>(result[0]);
				emulator->write_register<x86::reg::rbx, std::int32_t>(result[1]);
				emulator->write_register<x86::reg::rcx, std::int32_t>(result[2]);
				emulator->write_register<x86::reg::rdx, std::int32_t>(result[3]);

				return true;
			},
			emulator_t::default_start_address,
			emulator_t::default_end_address
		).error_or({});

		error.throw_if("instruction hook attach");

		set_up_driver_entry(emulator);

		run_main_module(emulator, entry_point_address);

		const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
		const auto rax = emulator->read_register<x86::reg::rax, emulator_t::address_type>();

		GLOBAL_LOG("emulation finished at rip=0x{:X}, rax=0x{:X}", rip, rax);

		error.throw_if("emulation running");
	}
	catch (const std::exception& e)
	{
		GLOBAL_ERR_LOG(e.what());
	}

	return 0;
}
