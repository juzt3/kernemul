#include "emulator/backend/hypermulator_backend.hpp"
#include "emulator/backend/unicorn_backend.hpp"
#include "emulator/object.hpp"
#include "event/event.hpp"
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

static void set_up_user_shared_data(const std::shared_ptr<emulator_t>& emulator)
{
	/*_KUSER_SHARED_DATA contents = { };

	contents.NtBuildNumber = 19045;
	contents.NtMajorVersion = 10;
	contents.NtMinorVersion = 0;

	kernel::user_shared_data = emulator_object_t<_KUSER_SHARED_DATA>::allocate_at(emulator, contents, 0xFFFFF78000000000);*/

	const auto contents = reinterpret_cast<const _KUSER_SHARED_DATA*>(0x7FFE0000);

	emulator_object_t<_KUSER_SHARED_DATA>::allocate_at(emulator, *contents, 0xFFFFF78000000000);
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

static emulator_object_t<_DRIVER_OBJECT> set_up_driver_entry(const std::shared_ptr<emulator_t>& emulator)
{
	auto driver_object = set_up_driver_object(emulator, *kernel::emulated_module);
	const auto registry_path = kernel::allocate_unicode_string_object(emulator, EMULATED_MODULE_REG_PATH, "RegistryPath");

	emulator->write_register<x86::reg::rcx>(driver_object.address());
	emulator->write_register<x86::reg::rdx>(registry_path.address());

	return driver_object;
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

struct lock_array_t
{
	std::uint8_t pad[0x68];
	std::uint64_t non_paged_pool_lock;
	std::uint8_t pad1[0xF90];
};

static emulator_object_t<lock_array_t> set_up_lock_array(const std::shared_ptr<emulator_t>& emulator, const std::shared_ptr<kernel_image_t>& nt_image)
{
	lock_array_t contents = { };

	contents.non_paged_pool_lock = nt_image->find_symbol("NonPagedPoolLock").value();

	return emulator_object_t<lock_array_t>::allocate(emulator, contents, "KPCR.LockArray");
}

static emulator_object_t<_KPCR> set_up_kpcr(const std::shared_ptr<emulator_t>& emulator,
	const std::shared_ptr<kernel_image_t>& nt_image,
	const std::shared_ptr<thread_t>& thread)
{
	const auto kprcb = set_up_kprcb(emulator, thread);

	auto kpcr = emulator_object_t<_KPCR>::allocate(emulator);
	auto lock_array = set_up_lock_array(emulator, nt_image);

	_KPCR contents = { };

	contents.Self = reinterpret_cast<_KPCR*>(kpcr.address());
	contents.CurrentPrcb = reinterpret_cast<_KPRCB*>(kprcb.address());
	contents.LockArray = reinterpret_cast<_KSPIN_LOCK_QUEUE*>(lock_array.address());

	kpcr.write(contents);

	return kpcr;
}

static void set_up_ntoskrnl_globals(const std::shared_ptr<emulator_t>& emulator, const std::shared_ptr<kernel_image_t>& nt_image)
{
	// MmPfnDatabase - allocate a fake PFN database and write its address
	if (const auto symbol = nt_image->find_symbol("MmPfnDatabase"))
	{
		constexpr emulator_t::size_type pfn_db_size = 0x10000;
		const auto pfn_db = emulator->heap_allocate(pfn_db_size, prot_read_write, true);
		emulator_err_t error = pfn_db.error_or({});
		error.throw_if("allocate fake PFN database");

		const auto pfn_db_address = *pfn_db;
		error = emulator->write_virtual_memory(*symbol, &pfn_db_address, sizeof(pfn_db_address));
		error.throw_if("write MmPfnDatabase");

		GLOBAL_LOG("initialized MmPfnDatabase at 0x{:X} -> 0x{:X}", *symbol, pfn_db_address);
	}

	// NtBuildNumber - Windows 10 22H2 free build
	if (const auto symbol = nt_image->find_symbol("NtBuildNumber"))
	{
		constexpr std::uint32_t build_number = 0xF0004A65; // 19045 | 0xF0000000 (free build)
		const emulator_err_t error = emulator->write_virtual_memory(*symbol, &build_number, sizeof(build_number));
		error.throw_if("write NtBuildNumber");

		GLOBAL_LOG("initialized NtBuildNumber at 0x{:X} -> 0x{:X}", *symbol, build_number);
	}

	// KiProcessorBlock - allocate a single processor block entry pointing to the KPRCB
	if (const auto symbol = nt_image->find_symbol("KiProcessorBlock"))
	{
		// single entry array - entry 0 will be filled later when KPRCB is set up
		constexpr std::uint64_t placeholder = 0;
		const emulator_err_t error = emulator->write_virtual_memory(*symbol, &placeholder, sizeof(placeholder));
		error.throw_if("write KiProcessorBlock");

		GLOBAL_LOG("initialized KiProcessorBlock at 0x{:X}", *symbol);
	}

	// MmHighestUserAddress
	if (const auto symbol = nt_image->find_symbol("MmHighestUserAddress"))
	{
		constexpr std::uint64_t highest_user = 0x00007FFFFFFEFFFF;
		const emulator_err_t error = emulator->write_virtual_memory(*symbol, &highest_user, sizeof(highest_user));
		error.throw_if("write MmHighestUserAddress");
	}

	// MmSystemRangeStart
	if (const auto symbol = nt_image->find_symbol("MmSystemRangeStart"))
	{
		constexpr std::uint64_t system_range = 0xFFFF800000000000;
		const emulator_err_t error = emulator->write_virtual_memory(*symbol, &system_range, sizeof(system_range));
		error.throw_if("write MmSystemRangeStart");
	}

	// initialize empty LIST_ENTRY heads in ntoskrnl that the driver walks
	const char* list_head_symbols[] = {
		"PiDDBCacheList",
		"CallbackListHead",
	};

	for (const auto* name : list_head_symbols)
	{
		if (const auto symbol = nt_image->find_symbol(name))
		{
			const std::uint64_t self_ptr = *symbol;
			emulator_err_t error = emulator->write_virtual_memory(*symbol, &self_ptr, sizeof(self_ptr));
			error.throw_if(std::format("write {}.Flink", name));

			error = emulator->write_virtual_memory(*symbol + sizeof(std::uint64_t), &self_ptr, sizeof(self_ptr));
			error.throw_if(std::format("write {}.Blink", name));

			GLOBAL_LOG("initialized {} at 0x{:X} (empty list)", name, *symbol);
		}
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

std::string to_string(const std::wstring_view view)
{
	std::string str = { };

	for (const auto c : view)
	{
		if (128 < static_cast<std::uint16_t>(c))
		{
			str.push_back('?');

			continue;
		}

		str.push_back(static_cast<char>(c));
	}

	return str;
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

		// system/currentcontrolset/control and subkeys
		static_cast<void>(kernel::registry->create_key("system/currentcontrolset/control"));
		kernel::registry->create_key("system/currentcontrolset/control/ci")->set_dword("Protected", 0);
		static_cast<void>(kernel::registry->create_key("system/currentcontrolset/control/wmi/restrictions"));

		// software version key
		{
			const auto winver_key = kernel::registry->create_key("software/microsoft/windows/currentversion");
			winver_key->set_string("BuildLab", L"19041.vb_release.191206-1406");
			winver_key->set_string("CurrentBuildNumber", L"19045");
			winver_key->set_string("ProgramFilesDir", L"C:\\Program Files");
			winver_key->set_string("ProgramFilesDir (x86)", L"C:\\Program Files (x86)");
		}

		// system start options
		kernel::registry->create_key("system/currentcontrolset/control")
			->set_string("SystemStartOptions", L"NOEXECUTE=OPTIN");

		// certificate store keys
		static_cast<void>(kernel::registry->create_key("software/microsoft/systemcertificates/root/certificates"));
		static_cast<void>(kernel::registry->create_key("software/microsoft/systemcertificates/authroot/certificates"));
		static_cast<void>(kernel::registry->create_key("software/microsoft/systemcertificates/authroot/autoupdate"));
		static_cast<void>(kernel::registry->create_key("software/microsoft/systemcertificates/ca/certificates"));
		static_cast<void>(kernel::registry->create_key("software/microsoft/systemcertificates/flightroot/certificates"));

		// hardware enumeration keys
		static_cast<void>(kernel::registry->create_key("system/currentcontrolset/enum/pci"));
		static_cast<void>(kernel::registry->create_key("system/currentcontrolset/enum/display"));

		kernel::filesystem->load_at("ntoskrnl.exe", "system32/ntoskrnl.exe");
		kernel::filesystem->load_at("ntoskrnl.exe", "system32/drivers/ntoskrnl.exe");
		kernel::filesystem->load_at("HAL.dll", "system32/hal.dll");
		kernel::filesystem->load_at("CI.dll", "system32/ci.dll");
		kernel::filesystem->load_at("kd.dll", "system32/kd.dll");
		kernel::filesystem->load_at("cng.sys", "system32/drivers/cng.sys");
		kernel::filesystem->load_at("FLTMGR.SYS", "system32/drivers/fltmgr.sys");
		kernel::filesystem->load_at("tbs.sys", "system32/drivers/tbs.sys");
		kernel::filesystem->load_at("tdi.sys", "system32/drivers/tdi.sys");
		kernel::filesystem->load_at("WdfLdr.sys", "system32/drivers/wdfldr.sys");
		kernel::filesystem->load_at("ntdll.dll", "system32/ntdll.dll");
		kernel::filesystem->load_at("win32k.sys", "system32/win32k.sys");
		kernel::filesystem->load_at("win32u.dll", "system32/win32u.dll");
		kernel::filesystem->load_directory_at("cat_root", "system32/catroot/");

		// load the emulated driver file so it can find itself on disk
		kernel::filesystem->load_at(EMULATED_MODULE_NAME,
			to_string(EMULATED_MODULE_DIRECTORY) + EMULATED_MODULE_NAME);

		// also register under system32/drivers/ since some drivers look themselves up there
		kernel::filesystem->load_at(EMULATED_MODULE_NAME,
			"system32/drivers/" + std::string(EMULATED_MODULE_NAME));

		// create the driver's installation directory so NtCreateFile on it succeeds
		{
			auto dir_path = to_string(EMULATED_MODULE_DIRECTORY);
			for (auto& c : dir_path)
			{
				if (c == '\\') c = '/';
				c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
			}
			while (!dir_path.empty() && dir_path.back() == '/')
				dir_path.pop_back();
			static_cast<void>(kernel::filesystem->create_directory_at(dir_path));
		}

		static_cast<void>(kernel::filesystem->create_at("physicaldrive0"));
		static_cast<void>(kernel::filesystem->create_at("physicaldrive1"));
		static_cast<void>(kernel::filesystem->create_at("physicaldrive2"));
		static_cast<void>(kernel::filesystem->create_at("physicaldrive3"));
		static_cast<void>(kernel::filesystem->create_at("physicaldrive4"));

		// create directories so NtCreateFile on \SystemRoot and prefetch succeeds
		static_cast<void>(kernel::filesystem->create_directory_at("windows"));
		static_cast<void>(kernel::filesystem->create_directory_at("prefetch"));


		// machine guid file
		{
			const std::string guid_content = "12345678-1234-1234-1234-123456789ABC";
			std::vector<std::uint8_t> guid_data(guid_content.begin(), guid_content.end());
			auto guid_file = kernel::filesystem->create_at("system32/restore/machineguid.txt");
			guid_file->write(guid_data);
		}

		set_up_stack(*emulator);
		set_up_user_shared_data(emulator);

		// todo: check load order of these drivers
		const auto nt_image = kernel::map_kernel_image(emulator, "ntoskrnl.exe", false);
		kernel::map_kernel_image(emulator, "HAL.dll", false);
		kernel::map_kernel_image(emulator, "CI.dll", false);
		kernel::map_kernel_image(emulator, "kd.dll", false);
		kernel::map_kernel_image(emulator, "win32k.sys", false);
		kernel::map_kernel_image(emulator, "cng.sys", false, L"\\SystemRoot\\System32\\drivers\\");
		kernel::map_kernel_image(emulator, "FLTMGR.SYS", false, L"\\SystemRoot\\System32\\drivers\\");
		kernel::map_kernel_image(emulator, "tbs.sys", false, L"\\SystemRoot\\System32\\drivers\\");
		kernel::map_kernel_image(emulator, "tdi.sys", false, L"\\SystemRoot\\System32\\drivers\\");
		kernel::map_kernel_image(emulator, "WdfLdr.sys", false, L"\\SystemRoot\\System32\\drivers\\");
		kernel::map_kernel_image(emulator, "ndis.sys", false, L"\\SystemRoot\\System32\\drivers\\");

		kernel::emulated_module = kernel::map_kernel_image(emulator, EMULATED_MODULE_NAME, true, EMULATED_MODULE_DIRECTORY);

		set_up_ntoskrnl_globals(emulator, nt_image);

		// create \Driver\X objects for all loaded modules
		for (const auto& module : kernel::module_entries)
		{
			auto name = module->name();

			// strip extension
			const auto dot = name.find_last_of('.');
			if (dot != std::string::npos)
			{
				name = name.substr(0, dot);
			}

			// lowercase
			for (auto& c : name)
			{
				c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
			}

			_DRIVER_OBJECT drv = {};
			drv.DriverStart = reinterpret_cast<void*>(module->base_address());
			drv.DriverSize = static_cast<std::uint32_t>(module->size());
			drv.DriverSection = reinterpret_cast<void*>(module->table_entry().address());

			const auto obj = emulator_object_t<_DRIVER_OBJECT>::allocate(emulator, drv, std::format("Driver\\{}", name));
			kernel::driver_objects[name] = obj.address();
		}

		// also add common driver names that may not be loaded but are queried
		const char* extra_drivers[] = { "pci", "acpi", "disk", "volmgr", "partmgr", "mountmgr", "ndis" };
		for (const auto* drv_name : extra_drivers)
		{
			if (!kernel::driver_objects.contains(drv_name))
			{
				_DRIVER_OBJECT drv = {};
				const auto obj = emulator_object_t<_DRIVER_OBJECT>::allocate(emulator, drv, std::format("Driver\\{}", drv_name));
				kernel::driver_objects[drv_name] = obj.address();
			}
		}

		GLOBAL_LOG("created {} driver objects", kernel::driver_objects.size());

		set_up_interrupt_flag(emulator);

		kernel::set_up_initial_system_process(emulator);

		const auto current_thread_id = kernel::object_manager->allocate_id();

		const auto& system_process = kernel::process_entries.front();
		kernel::current_thread = kernel::create_thread(emulator, current_thread_id, system_process);

		kernel::set_up_gdt(emulator);
		kernel::set_up_segments(emulator);
		kernel::set_up_idt(emulator, *nt_image);

		const auto kpcr = set_up_kpcr(emulator, nt_image, kernel::current_thread);
		kernel::set_up_kernel_gs(emulator, kpcr.address());
		kernel::kpcr_address = kpcr.address();

		// write KPRCB address to KiProcessorBlock[0] now that KPCR is set up
		if (const auto ki_proc_block = nt_image->find_symbol("KiProcessorBlock"))
		{
			_KPCR kpcr_contents = {};
			static_cast<void>(emulator->read_virtual_memory(kpcr.address(), &kpcr_contents, sizeof(kpcr_contents)));

			const auto prcb_address = reinterpret_cast<std::uint64_t>(kpcr_contents.CurrentPrcb);
			static_cast<void>(emulator->write_virtual_memory(*ki_proc_block, &prcb_address, sizeof(prcb_address)));

			kernel::kprcb_address = prcb_address;
			GLOBAL_LOG("initialized KPRCB at 0x{:X}", prcb_address);
		}

		// write CurrentThread to the embedded KPRCB location at KPCR+0x180
		// in real Windows, gs:[0x188] = KPCR.Prcb.CurrentThread
		// KPRCB is embedded at KPCR+0x180, CurrentThread is at KPRCB+0x8
		{
			constexpr std::uint64_t kprcb_embedded_offset = 0x180;
			const auto thread_address = kernel::current_thread->address();
			static_cast<void>(emulator->write_virtual_memory(
				kpcr.address() + kprcb_embedded_offset + offsetof(_KPRCB, CurrentThread),
				&thread_address, sizeof(thread_address)));
			GLOBAL_LOG("wrote CurrentThread 0x{:X} to KPCR+0x188", thread_address);
		}

		set_up_lstar_msr(emulator, nt_image);

		const emulator_t::address_type base_address = kernel::emulated_module->base_address();
		const emulator_t::address_type entry_point_address = kernel::emulated_module->entry_point();

		GLOBAL_LOG("mapped ntoskrnl at 0x{:X}", nt_image->base_address());
		GLOBAL_LOG("mapped image at 0x{:X}", base_address);

		const auto redirect_execute_handler = [emulator]
		([[maybe_unused]] const emulator_t::address_type accessed_address, [[maybe_unused]] const protection_t protection)
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
				const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

				emulator_t::address_type return_address = 0;

				const emulator_err_t read_error = emulator->read_virtual_memory(rsp, &return_address, sizeof(return_address));

				read_error.throw_if("read from stack");

				if (const auto redirected_function = kernel::find_redirected_function(rip))
				{
					THREAD_LOG("redirecting function at 0x{:X} (return address=0x{:X})", rip, return_address);

					bool skip_return = false;

					(*redirected_function)(skip_return);

					if (!skip_return)
					{
						emulator->write_register<x86::reg::rsp>(rsp + 8);
						emulator->write_register<x86::reg::rip>(return_address);
					}

					rflags flags = emulator->read_register<x86::reg::rflags, rflags>();

					if (flags.trap_flag)
					{
						flags.trap_flag = 0;

						emulator->write_register<x86::reg::rflags>(flags.flags);
					}

					emulator->cancel_pending_single_step();

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

				static_cast<void>(emulator->stop());

				emulator->cancel_pending_single_step();
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
				const auto rcx = emulator->read_register<x86::reg::rcx, std::int32_t>();

				THREAD_LOG("cpuid executed at 0x{:X} (rax=0x{:X}, rcx=0x{:X})", rip, rax, rcx);

				std::array<std::int32_t, 4> result;

				__cpuidex(result.data(), rax, rcx);

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

		error = emulator->hook_invalid_memory(
			[emulator](const emulator_t::address_type faulting_address, const protection_t access) -> bool
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				THREAD_ERR_LOG("invalid memory access at 0x{:X} (rip=0x{:X}, access={})",
					faulting_address, rip, static_cast<std::uint32_t>(access));
				THREAD_ERR_LOG("  rax=0x{:X} rbx=0x{:X} rcx=0x{:X} rdx=0x{:X}",
					emulator->read_register<x86::reg::rax, std::uint64_t>(),
					emulator->read_register<x86::reg::rbx, std::uint64_t>(),
					emulator->read_register<x86::reg::rcx, std::uint64_t>(),
					emulator->read_register<x86::reg::rdx, std::uint64_t>());
				THREAD_ERR_LOG("  rsi=0x{:X} rdi=0x{:X} rbp=0x{:X} rsp=0x{:X}",
					emulator->read_register<x86::reg::rsi, std::uint64_t>(),
					emulator->read_register<x86::reg::rdi, std::uint64_t>(),
					emulator->read_register<x86::reg::rbp, std::uint64_t>(),
					emulator->read_register<x86::reg::rsp, std::uint64_t>());

				return false;
			},
			prot_all,
			emulator_t::default_start_address,
			emulator_t::default_end_address
		).error_or({});

		error.throw_if("monitor invalid memory");

		error = emulator->hook_msr(
			[emulator](const std::uint32_t msr_number, const bool write)
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				kernel::handle_exception(emulator, rip, 0, 0);

				THREAD_LOG("msr 0x{:X} accessed at 0x{:X} (write={})", msr_number, rip, write);
			}
		).error_or({});

		error.throw_if("instruction hook attach");

		/*error = emulator->hook_basic_block(
			[emulator]()
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				THREAD_LOG("basic block executed at 0x{:X}", rip);
			},
			kernel::emulated_module->base_address(),
			kernel::emulated_module->base_address() + kernel::emulated_module->size()
		).error_or({});

		error.throw_if("basic block hook attach");*/

		const auto current_cr3 = emulator->read_register<x86::reg::cr3, cr3>();

		emulator->map_virtual_page(0xFFFFF0F87C3E1000, current_cr3.address_of_page_directory << 12);
		emulator->map_virtual_page(0xFFFFF0F87C3FF000, current_cr3.address_of_page_directory << 12);

		kernel::driver_object = set_up_driver_entry(emulator);

		kernel::main_thread = kernel::current_thread;

		event_runner_t runner(emulator);
		runner.load_folder("events/");

		kernel::run_all_threads(emulator, entry_point_address,
			[&runner](const std::shared_ptr<thread_t>& finished)
			{
				runner.on_thread_done(finished);
			});

		const auto rax = emulator->read_register<x86::reg::rax, emulator_t::address_type>();
		GLOBAL_LOG("emulation finished (rax=0x{:X})", rax);

		if (!runner.results().empty())
		{
			GLOBAL_LOG("processed {} events", runner.results().size());
		}

		error.throw_if("emulation running");
	}
	catch (const std::exception& e)
	{
		GLOBAL_ERR_LOG(e.what());
	}

	return 0;
}
