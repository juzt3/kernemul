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

		/*const emulator_err_t error = emulator->hook_code(
			[emulator, dbgctl_runtime_address]()
			{
				emulator->write_register<x86::reg::rdx>(0);
				emulator->write_register<x86::reg::rax>(3);
				emulator->write_register<x86::reg::rip>(dbgctl_runtime_address + 4);
			},
			dbgctl_runtime_address,
			dbgctl_runtime_address + 1
		).error_or({});

		error.throw_if("place MSR hook stub");*/
	}
}

static void patch_is_address_valid_routine(const std::shared_ptr<emulator_t>& emulator)
{
	const auto image_buffer = kernel::emulated_module->buffer();
	const auto image = reinterpret_cast<const portable_executable::image_t*>(image_buffer.data());

	if (const auto reference_signature = image->signature_scan("E8 ? ? ? ? 4C 8B F8"))//"48 8B CF E9 ? ? ? ? E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? 83 FE"))
	{
		constexpr std::size_t call_signature_offset = 0;
		constexpr std::size_t call_imm_offset = 1;
		constexpr std::size_t call_size = 5;

		const auto call_local_address = reference_signature + call_signature_offset;
		const auto rip_local_address = call_local_address + call_size;

		const auto routine_local_address = rip_local_address + *reinterpret_cast<const std::int32_t*>(call_local_address + call_imm_offset);

		const std::int64_t routine_rva = routine_local_address - image_buffer.data();
		const emulator_t::address_type routine_runtime_address = kernel::emulated_module->base_address() + routine_rva;

		constexpr std::array<std::uint8_t, 3> stub = {
			//0xB0, 0x01, // mov al, 1
			0x30, 0xC0, // xor al, al
			0xC3 // ret
		};

		const emulator_err_t error = emulator->write_virtual_memory(routine_runtime_address, stub);

		error.throw_if("write 'is address valid' stub memory");

		/*const emulator_err_t error = emulator->hook_code(
			[emulator]()
			{
				emulator->write_register<x86::reg::rax>(0);

				const auto rsp = emulator->read_register<x86::reg::rsp, std::uint64_t>();

				std::uint64_t return_address = 0;

				emulator->read_virtual_memory(rsp, &return_address, sizeof(return_address)).throw_if("read return address");

				emulator->write_register<x86::reg::rsp>(rsp + 8);
				emulator->write_register<x86::reg::rip>(return_address);
			},
			routine_runtime_address,
			routine_runtime_address + 1
		).error_or({});

		error.throw_if("place 'is address valid' hook stub");*/
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
		kernel::map_kernel_image(emulator, "win32k.sys", false);
		kernel::map_kernel_image(emulator, "cng.sys", false, L"\\SystemRoot\\System32\\drivers\\");
		kernel::map_kernel_image(emulator, "FLTMGR.SYS", false, L"\\SystemRoot\\System32\\drivers\\");
		kernel::map_kernel_image(emulator, "tbs.sys", false, L"\\SystemRoot\\System32\\drivers\\");
		kernel::map_kernel_image(emulator, "tdi.sys", false, L"\\SystemRoot\\System32\\drivers\\");
		kernel::map_kernel_image(emulator, "WdfLdr.sys", false, L"\\SystemRoot\\System32\\drivers\\");

		kernel::emulated_module = kernel::map_kernel_image(emulator, EMULATED_MODULE_NAME, true, EMULATED_MODULE_DIRECTORY);

		/*emulator->hook_basic_block([emulator]()
			{
				spdlog::info("basic block executed at 0x{:X}", emulator->read_register<x86::reg::rip, std::uint64_t>());
			}, kernel::emulated_module->base_address(),
				kernel::emulated_module->base_address() + kernel::emulated_module->size()
		);*/

		//patch_dbgctl_check(emulator);
		//patch_is_address_valid_routine(emulator);
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

		error = emulator->hook_invalid_memory(
			[](const emulator_t::address_type faulting_address, const protection_t access) -> bool
			{
				THREAD_LOG("invalid memory accessed at 0x{:X} (access={})", faulting_address, static_cast<std::uint32_t>(access));

				return false;
			},
			prot_all,
			emulator_t::default_start_address,
			emulator_t::default_end_address
		).error_or({});

		error.throw_if("monitor invalid memory");

		error = emulator->hook_instruction(x86::insn::rdtsc,
			[emulator]()
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				THREAD_LOG("rdtsc executed at 0x{:X}", rip);

				return false;
			},
			emulator_t::default_start_address,
			emulator_t::default_end_address
		).error_or({});

		error.throw_if("instruction hook attach");

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

		set_up_driver_entry(emulator);

		kernel::run_all_threads(emulator, entry_point_address);

		const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
		const auto rax = emulator->read_register<x86::reg::rax, emulator_t::address_type>();
		const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
		const auto rdx = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
		const auto rsi = emulator->read_register<x86::reg::rsi, emulator_t::address_type>();

		GLOBAL_LOG("emulation finished at rip=0x{:X}, rax=0x{:X}, rcx=0x{:X}, rdx=0x{:X}, rdi=0x{:X}", rip, rax, rcx, rdx, rsi);

		error.throw_if("emulation running");
	}
	catch (const std::exception& e)
	{
		GLOBAL_ERR_LOG(e.what());
	}

	return 0;
}
