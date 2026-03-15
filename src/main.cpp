#include "emulator/backend/hypermulator_backend.hpp"
#include "emulator/backend/unicorn_backend.hpp"
#include "emulator/object.hpp"
#include "kernel/kernel.hpp"
#include "kernel/image_loader.hpp"
#include "kernel/segments.hpp"
#include "config.hpp"

#include <spdlog/spdlog.h>

static void set_up_user_shared_data(const std::shared_ptr<emulator_t>& emulator)
{
	_KUSER_SHARED_DATA contents = { };

	contents.NtBuildNumber = 19045;
	contents.NtMajorVersion = 10;
	contents.NtMinorVersion = 0;

	kernel::user_shared_data = emulator_object_t<_KUSER_SHARED_DATA>::allocate_at(emulator, contents, 0xFFFFF78000000000);
}

static emulator_object_t<_DRIVER_OBJECT> set_up_driver_object(const std::shared_ptr<emulator_t>& emulator, const mapped_image_t& image)
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
	const auto registry_path = allocate_unicode_string_object(emulator, EMULATED_MODULE_REG_PATH, "RegistryPath");

	emulator->write_register<x86::reg::rcx>(driver_object.address());
	emulator->write_register<x86::reg::rdx>(registry_path.address());
}

static void set_up_ps_loaded_module_list(const std::shared_ptr<emulator_t>& emulator)
{
	kernel::ps_loaded_module_list = emulator_object_t<_LIST_ENTRY>::allocate(emulator, "PsLoadedModuleList");
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

static emulator_object_t<_KPRCB> set_up_kprcb(const std::shared_ptr<emulator_t>& emulator)
{
	return emulator_object_t<_KPRCB>::allocate(emulator);
}

static emulator_object_t<_KPCR> set_up_kpcr(const std::shared_ptr<emulator_t>& emulator)
{
	const auto kprcb = set_up_kprcb(emulator);

	auto kpcr = emulator_object_t<_KPCR>::allocate(emulator);

	_KPCR contents = { };

	contents.Self = reinterpret_cast<_KPCR*>(kpcr.address());
	contents.CurrentPrcb = reinterpret_cast<_KPRCB*>(kprcb.address());

	kpcr.write(contents);

	return kpcr;
}

std::int32_t main()
{
	try
	{
		const auto emulator = std::static_pointer_cast<emulator_t>(std::make_shared<hypermulator_t>());

		kernel::filesystem = std::make_shared<filesystem_t>();

		set_up_stack(*emulator);
		set_up_ps_loaded_module_list(emulator);
		set_up_user_shared_data(emulator);

		const auto nt_image = map_kernel_image(emulator, "ntoskrnl.exe", false);
		map_kernel_image(emulator, "HAL.dll", false);
		map_kernel_image(emulator, "CI.dll", false);
		map_kernel_image(emulator, "cng.sys", false, L"\\SystemRoot\\System32\\drivers\\");
		map_kernel_image(emulator, "FLTMGR.SYS", false, L"\\SystemRoot\\System32\\drivers\\");

		kernel::emulated_module = map_kernel_image(emulator, EMULATED_MODULE_NAME, true, EMULATED_MODULE_DIRECTORY);

		set_up_gdt(emulator);
		set_up_segments(emulator);
		set_up_idt(emulator, *nt_image);

		const auto kpcr = set_up_kpcr(emulator);
		set_up_kernel_gs(emulator, kpcr.address());

	    const emulator_t::address_type base_address = kernel::emulated_module->base_address();
		const emulator_t::address_type entry_point_address = kernel::emulated_module->entry_point();

		spdlog::info("mapped ntoskrnl at 0x{:X}", nt_image->base_address());
		spdlog::info("mapped image at 0x{:X}", base_address);

		emulator_err_t error = emulator->hook_basic_block(
			[emulator, &nt_image]()
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
				const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

				emulator_t::address_type return_address = 0;

				const emulator_err_t read_error = emulator->read_virtual_memory(rsp, &return_address, sizeof(return_address));

				read_error.throw_if("read from stack");

				if (const auto redirected_function = kernel::find_redirected_function(rip))
				{
					spdlog::info("redirecting function at 0x{:X} (return address=0x{:X}) rcx=0x{:X}", rip, return_address, emulator->read_register<x86::reg::rcx, emulator_t::address_type>());

					bool skip_return = false;

					(*redirected_function)(skip_return);

					if (!skip_return)
					{
						emulator->write_register<x86::reg::rsp>(rsp + 8);
						emulator->write_register<x86::reg::rip>(return_address);
					}
				}
				else
				{
					std::string symbol_name;

					for (const auto& [name, address] : nt_image->symbols())
					{
						if (address == rip)
						{
							symbol_name = name;
							break;
						}
					}

					if (!symbol_name.empty())
					{
						spdlog::error("unimplemented function '{}' (address=0x{:X}, return address=0x{:X})", symbol_name, rip, return_address);
					}
					else
					{
						spdlog::error("unimplemented non-symbol function (address=0x{:X}, return address=0x{:X})", rip, return_address);
					}

					emulator->write_register<x86::reg::rip, emulator_t::address_type>(-1);
				}
			},
			nt_image->base_address(),
			nt_image->base_address() + nt_image->size()
		).error_or({});
		 
		error.throw_if("basic block hook attach");

		error = emulator->hook_instruction(x86::insn::cpuid,
			[emulator]()
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
				const auto rax = emulator->read_register<x86::reg::rax, emulator_t::address_type>();

				spdlog::info("cpuid executed at 0x{:X} (rax=0x{:X})", rip, rax);

				return false;
			},
			emulator_t::default_start_address,
			emulator_t::default_end_address
		).error_or({});

		error.throw_if("instruction hook attach");

		error = emulator->hook_instruction(x86::insn::rdtsc,
			[emulator]()
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				spdlog::info("rdtsc executed at 0x{:X}", rip);

				return false;
			},
			emulator_t::default_start_address,
			emulator_t::default_end_address
		).error_or({});

		error.throw_if("instruction hook attach");

		set_up_driver_entry(emulator);

		error = emulator->run_at(entry_point_address, emulator_t::thread_return_address);

		const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

		spdlog::info("emulation finished at rip=0x{:X}", rip);

		error.throw_if("emulation running");
	}
	catch (const std::exception& e)
	{
		spdlog::error(e.what());
	}

	return 0;
}
