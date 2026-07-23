#include "user.hpp"
#include "user_memory.hpp"
#include "user_defs.hpp"
#include "syscall_table.hpp"
#include "exception_dispatch.hpp"
#include "../kernel/kernel.hpp"
#include "../kernel/kernel_string.hpp"
#include "../kernel/image_loader.hpp"
#include "../kernel/segments.hpp"
#include "../impl/win32k/w32_helpers.hpp"
#include "../impl/ntoskrnl/nt_syscall.hpp"

#include "../util/logs.hpp"
#include "../util/file.hpp"
#include "../util/util.hpp"

#include <portable_executable/image.hpp>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

static emulator_t::address_type user_page_allocator(const std::size_t size)
{
	return user::memory_manager->allocate_pages(size);
}

static void set_unicode_string(
	user::unicode_string64_t& str,
	const emulator_t::address_type string_address,
	const std::uint16_t byte_length)
{
	str.Length = byte_length;
	str.MaximumLength = static_cast<std::uint16_t>(byte_length + sizeof(wchar_t));
	str.Buffer = string_address;
}

static emulator_t::address_type build_environment(
	const std::shared_ptr<emulator_t>& emulator)
{
	std::vector<wchar_t> env;

	const auto add = [&env](const std::wstring_view entry)
	{
		env.insert(env.end(), entry.begin(), entry.end());
		env.push_back(L'\0');
	};

	add(L"=C:=C:\\Windows\\System32");
	add(L"COMPUTERNAME=DESKTOP");
	add(std::wstring{L"NUMBER_OF_PROCESSORS="} + std::to_wstring(kernel::processor_count));
	add(L"OS=Windows_NT");
	add(L"PATH=C:\\Windows\\System32;C:\\Windows");
	add(L"PATHEXT=.COM;.EXE;.BAT;.CMD");
	add(L"PROCESSOR_ARCHITECTURE=AMD64");
	add(L"SystemDrive=C:");
	add(L"SystemRoot=C:\\Windows");
	add(L"TEMP=C:\\Windows\\Temp");
	add(L"TMP=C:\\Windows\\Temp");
	add(L"windir=C:\\Windows");
	env.push_back(L'\0');

	const auto byte_size = env.size() * sizeof(wchar_t);
	const auto address = user::memory_manager->allocate_pages(byte_size);

	if (address)
	{
		static_cast<void>(emulator->write_virtual_memory(address, env.data(), byte_size));
		GLOBAL_LOG("user: environment block at 0x{:X} ({} bytes)", address, byte_size);
	}

	return address;
}

static emulator_t::address_type try_load_api_set_from_pe(
	const std::shared_ptr<emulator_t>& emulator,
	const std::vector<std::uint8_t>& data)
{
	if (data.size() < sizeof(portable_executable::dos_header_t))
	{
		return 0;
	}

	const auto* pe = reinterpret_cast<const portable_executable::image_t*>(data.data());

	if (!pe->dos_header()->valid())
	{
		return 0;
	}

	const portable_executable::section_header_t* section = nullptr;

	for (const auto& s : pe->sections())
	{
		if (std::strncmp(s.name, ".apiset", 7) == 0)
		{
			section = &s;
			break;
		}
	}

	if (!section || section->pointer_to_raw_data == 0 || section->size_of_raw_data == 0)
	{
		return 0;
	}

	const auto section_size = static_cast<std::size_t>(section->size_of_raw_data);
	const auto section_offset = static_cast<std::size_t>(section->pointer_to_raw_data);

	if (section_offset + section_size > data.size())
	{
		return 0;
	}

	const auto address = user::memory_manager->allocate_pages(section_size);

	if (!address)
	{
		return 0;
	}

	static_cast<void>(emulator->write_virtual_memory(
		address, data.data() + section_offset, section_size));

	GLOBAL_LOG("user: ApiSetMap from apisetschema.dll ({} bytes) at 0x{:X}",
		section_size, address);

	return address;
}

static emulator_t::address_type build_api_set_map(
	const std::shared_ptr<emulator_t>& emulator)
{
	const auto schema_data = util::read_file(std::filesystem::path("vfs") / "apisetschema.dll");

	if (schema_data)
	{
		GLOBAL_LOG("user: read apisetschema.dll ({} bytes)", schema_data->size());

		const auto address = try_load_api_set_from_pe(emulator, *schema_data);

		if (address)
		{
			return address;
		}
	}

	GLOBAL_WARN_LOG("user: using empty ApiSetMap (fallback)");

	struct api_set_namespace_v6
	{
		std::uint32_t Version;
		std::uint32_t Size;
		std::uint32_t Flags;
		std::uint32_t Count;
		std::uint32_t EntryOffset;
		std::uint32_t HashOffset;
		std::uint32_t HashFactor;
	};

	static_assert(sizeof(api_set_namespace_v6) == 0x1C);

	const api_set_namespace_v6 ns =
	{
		.Version = 6,
		.Size = sizeof(api_set_namespace_v6),
		.Flags = 0,
		.Count = 0,
		.EntryOffset = sizeof(api_set_namespace_v6),
		.HashOffset = sizeof(api_set_namespace_v6),
		.HashFactor = 0,
	};

	const auto address = user::memory_manager->allocate_pages(sizeof(ns));

	if (address)
	{
		static_cast<void>(emulator->write_virtual_memory(address, &ns, sizeof(ns)));
		GLOBAL_LOG("user: synthetic ApiSetMap (V6, empty) at 0x{:X}", address);
	}

	return address;
}

struct ldr_module_info_t
{
	emulator_t::address_type base;
	emulator_t::size_type size;
	std::wstring full_path;
	std::wstring name;
	std::uint32_t flags;
	bool in_init_order;
};

static emulator_t::address_type build_ldr_data(
	const std::shared_ptr<emulator_t>& emulator,
	const std::vector<ldr_module_info_t>& modules)
{
	using namespace user;

	const auto ldr_address = user::memory_manager->allocate_pages(sizeof(peb_ldr_data64_t));

	if (!ldr_address)
	{
		throw std::runtime_error("user: failed to allocate PEB_LDR_DATA");
	}

	std::vector<emulator_t::address_type> entry_addresses;

	for (const auto& mod : modules)
	{
		const auto addr = user::memory_manager->allocate_pages(ldr_data_table_entry64_alloc_size);

		if (!addr)
		{
			throw std::runtime_error("user: failed to allocate LDR_DATA_TABLE_ENTRY");
		}

		entry_addresses.push_back(addr);
	}

	const auto count = modules.size();

	auto link_address = [](const emulator_t::address_type entry, const std::size_t offset)
	{
		return entry + offset;
	};

	auto next_link = [&](const std::size_t i, const std::size_t links_offset)
	{
		return (i + 1 < count)
			? link_address(entry_addresses[i + 1], links_offset)
			: ldr_address + links_offset + offsetof(peb_ldr_data64_t, InLoadOrderModuleList)
				- offsetof(ldr_data_table_entry64_t, InLoadOrderLinks);
	};

	auto prev_link = [&](const std::size_t i, const std::size_t links_offset)
	{
		return (i > 0)
			? link_address(entry_addresses[i - 1], links_offset)
			: ldr_address + links_offset + offsetof(peb_ldr_data64_t, InLoadOrderModuleList)
				- offsetof(ldr_data_table_entry64_t, InLoadOrderLinks);
	};

	for (std::size_t i = 0; i < count; ++i)
	{
		const auto& mod = modules[i];
		const auto addr = entry_addresses[i];

		const auto name_guest = kernel::allocate_wstring(*emulator, mod.name, user_page_allocator);
		const auto path_guest = kernel::allocate_wstring(*emulator, mod.full_path, user_page_allocator);

		ldr_data_table_entry64_t entry{};

		entry.DllBase = mod.base;
		entry.SizeOfImage = static_cast<std::uint32_t>(mod.size);
		entry.Flags = mod.flags;
		entry.ObsoleteLoadCount = 0xFFFF;

		set_unicode_string(entry.FullDllName, path_guest,
			static_cast<std::uint16_t>(mod.full_path.size() * sizeof(wchar_t)));
		set_unicode_string(entry.BaseDllName, name_guest,
			static_cast<std::uint16_t>(mod.name.size() * sizeof(wchar_t)));

		constexpr auto load_off = offsetof(ldr_data_table_entry64_t, InLoadOrderLinks);
		constexpr auto mem_off = offsetof(ldr_data_table_entry64_t, InMemoryOrderLinks);

		entry.InLoadOrderLinks.Flink = next_link(i, load_off);
		entry.InLoadOrderLinks.Blink = prev_link(i, load_off);
		entry.InMemoryOrderLinks.Flink = next_link(i, mem_off);
		entry.InMemoryOrderLinks.Blink = prev_link(i, mem_off);

		entry.HashLinks.Flink = addr + offsetof(ldr_data_table_entry64_t, HashLinks);
		entry.HashLinks.Blink = addr + offsetof(ldr_data_table_entry64_t, HashLinks);

		static_cast<void>(emulator->write_virtual_memory(addr, &entry, sizeof(entry)));
	}

	// wire InInitializationOrderLinks for modules that requested it
	{
		std::vector<std::size_t> init_indices;

		for (std::size_t i = 0; i < count; ++i)
		{
			if (modules[i].in_init_order)
			{
				init_indices.push_back(i);
			}
		}

		constexpr auto init_off = offsetof(ldr_data_table_entry64_t, InInitializationOrderLinks);
		const auto init_head = ldr_address + offsetof(peb_ldr_data64_t, InInitializationOrderModuleList);

		for (std::size_t j = 0; j < init_indices.size(); ++j)
		{
			const auto addr = entry_addresses[init_indices[j]];
			const auto flink = (j + 1 < init_indices.size())
				? entry_addresses[init_indices[j + 1]] + init_off
				: init_head;
			const auto blink = (j > 0)
				? entry_addresses[init_indices[j - 1]] + init_off
				: init_head;

			user::list_entry64_t links{ flink, blink };
			static_cast<void>(emulator->write_virtual_memory(addr + init_off, &links, sizeof(links)));
		}

		peb_ldr_data64_t ldr{};
		ldr.Length = sizeof(peb_ldr_data64_t);
		ldr.Initialized = 1;

		const auto first = entry_addresses.front();
		const auto last = entry_addresses.back();

		constexpr auto load_off = offsetof(ldr_data_table_entry64_t, InLoadOrderLinks);
		constexpr auto mem_off = offsetof(ldr_data_table_entry64_t, InMemoryOrderLinks);

		ldr.InLoadOrderModuleList = { first + load_off, last + load_off };
		ldr.InMemoryOrderModuleList = { first + mem_off, last + mem_off };

		if (init_indices.empty())
		{
			ldr.InInitializationOrderModuleList = { init_head, init_head };
		}
		else
		{
			ldr.InInitializationOrderModuleList =
			{
				entry_addresses[init_indices.front()] + init_off,
				entry_addresses[init_indices.back()] + init_off
			};
		}

		static_cast<void>(emulator->write_virtual_memory(ldr_address, &ldr, sizeof(ldr)));
	}

	GLOBAL_LOG("user: PEB_LDR_DATA at 0x{:X} ({} modules)", ldr_address, count);

	return ldr_address;
}

user::context_t user::set_up_structures(
	const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type image_base,
	const emulator_t::address_type ntdll_base,
	const emulator_t::size_type image_size,
	const emulator_t::size_type ntdll_size,
	const std::string_view module_name,
	const std::shared_ptr<process_t>& process,
	const std::vector<std::shared_ptr<image_t>>& extra_modules)
{
	using namespace user;

	constexpr emulator_t::size_type stack_size = 0x100000;

	const auto stack_limit = memory_manager->allocate_pages(stack_size);

	if (!stack_limit)
	{
		throw std::runtime_error("user: failed to allocate usermode stack");
	}

	const auto stack_base = stack_limit + stack_size;

	// PEB is allocated by kernel::create_process using the usermode allocator.
	const auto peb_address = process->peb_address();

	if (!peb_address)
	{
		throw std::runtime_error("user: process has no PEB allocation");
	}

	const auto teb_address = memory_manager->allocate_pages(teb64_alloc_size);

	if (!teb_address)
	{
		throw std::runtime_error("user: failed to allocate TEB");
	}

	// build environment block
	const auto env_address = build_environment(emulator);

	const auto api_set_address = build_api_set_map(emulator);

	const auto wide_module_name = util::widen_string(module_name);
	const auto wide_module_path = L"C:\\Windows\\System32\\" + wide_module_name;

	std::vector<ldr_module_info_t> ldr_modules =
	{
		{ image_base, image_size, wide_module_path, wide_module_name, 0x00004000, false },
		{ ntdll_base, ntdll_size, L"C:\\Windows\\System32\\ntdll.dll", L"ntdll.dll", 0x001C4004, true },
	};

	for (const auto& mod : extra_modules)
	{
		if (!mod)
		{
			continue;
		}

		const auto wide_name = util::widen_string(mod->name());
		const auto wide_path = L"C:\\Windows\\System32\\" + wide_name;

		ldr_modules.push_back({ mod->base_address(), mod->size(), wide_path, wide_name, 0x001C4004, true });
	}

	const auto ldr_address = build_ldr_data(emulator, ldr_modules);

	// allocate a zeroed page for GdiSharedHandleTable
	const auto gdi_table = memory_manager->allocate_pages(0x1000);

	// build RTL_USER_PROCESS_PARAMETERS
	const auto params_address = memory_manager->allocate_pages(rtl_user_process_parameters64_alloc_size);

	if (!params_address)
	{
		throw std::runtime_error("user: failed to allocate ProcessParameters");
	}

	{
		rtl_user_process_parameters64_t params{};

		params.MaximumLength = rtl_user_process_parameters64_alloc_size;
		params.Length = rtl_user_process_parameters64_alloc_size;
		params.Flags = 0x6001;

		params.ConsoleHandle = console_handle;
		params.StandardInput = stdin_handle;
		params.StandardOutput = stdout_handle;
		params.StandardError = stderr_handle;

		const std::wstring current_dir = L"C:\\Windows\\System32\\";
		const auto current_dir_address = kernel::allocate_wstring(*emulator, current_dir, user_page_allocator);
		set_unicode_string(params.CurrentDirectory.DosPath, current_dir_address,
			static_cast<std::uint16_t>(current_dir.size() * sizeof(wchar_t)));

		const std::wstring dll_path = L"C:\\Windows\\System32";
		const auto dll_path_address = kernel::allocate_wstring(*emulator, dll_path, user_page_allocator);
		set_unicode_string(params.DllPath, dll_path_address,
			static_cast<std::uint16_t>(dll_path.size() * sizeof(wchar_t)));

		const auto image_path = L"C:\\Windows\\System32\\" + wide_module_name;
		const auto image_path_address = kernel::allocate_wstring(*emulator, image_path, user_page_allocator);
		set_unicode_string(params.ImagePathName, image_path_address,
			static_cast<std::uint16_t>(image_path.size() * sizeof(wchar_t)));

		const auto command_line = wide_module_name;
		const auto command_line_address = kernel::allocate_wstring(*emulator, command_line, user_page_allocator);
		set_unicode_string(params.CommandLine, command_line_address,
			static_cast<std::uint16_t>(command_line.size() * sizeof(wchar_t)));

		params.Environment = env_address;

		static_cast<void>(emulator->write_virtual_memory(params_address, &params, sizeof(params)));

		GLOBAL_LOG("user: ProcessParameters at 0x{:X} (env=0x{:X}, stdout=0x{:X})",
			params_address, env_address, user::stdout_handle);
	}

	// build PEB
	{
		kernel::write_process_peb(emulator, peb_address, {
			.image_base_address = image_base,
			.ldr = ldr_address,
			.process_parameters = params_address,
			.api_set_map = api_set_address,
			.gdi_shared_handle_table = gdi_table,
		});

		GLOBAL_LOG("user: PEB at 0x{:X} (image_base=0x{:X}, params=0x{:X}, apiset=0x{:X})",
			peb_address, image_base, params_address, api_set_address);
	}

	// build TEB
	{
		teb64_t teb{};

		teb.NtTib.StackBase = stack_base;
		teb.NtTib.StackLimit = stack_limit;
		teb.NtTib.Self = teb_address;
		teb.ClientId.UniqueProcess = process->id();
		teb.ProcessEnvironmentBlock = peb_address;

		static_cast<void>(emulator->write_virtual_memory(teb_address, &teb, sizeof(teb)));

		// skip GetCurrentNlsCache - sogen sets TEB+0x179C to 1
		constexpr std::uint8_t skip_nls_cache = 1;
		static_cast<void>(emulator->write_virtual_memory(
			teb_address + 0x179C, &skip_nls_cache, sizeof(skip_nls_cache)));

		GLOBAL_LOG("user: TEB at 0x{:X}, stack=0x{:X}-0x{:X}",
			teb_address, stack_limit, stack_base);
	}

	return context_t
	{
		.teb_address = teb_address,
		.peb_address = peb_address,
		.stack_base = stack_base,
		.stack_limit = stack_limit,
		.image_base = image_base,
		.ntdll_base = ntdll_base,
		.process_parameters = params_address,
	};
}

std::shared_ptr<thread_t> user::create_initial_thread(
	const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type entry_point,
	const emulator_t::address_type ldr_initialize_thunk,
	const emulator_t::address_type rtl_user_thread_start,
	const context_t& context,
	const std::shared_ptr<process_t>& process)
{
	auto thread = kernel::create_thread_at(emulator, ldr_initialize_thunk, {},
		context.stack_base, context.teb_address, process);

	// place CONTEXT on the usermode stack for NtContinue after initialization
	const emulator_t::address_type stack_top = (context.stack_base - 0x1000) & ~0xFull;
	const emulator_t::address_type context_address = (stack_top - sizeof(CONTEXT)) & ~0xFull;

	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_FULL;
	ctx.MxCsr = 0x1F80;
	ctx.SegCs = kernel::user_cs_selector;
	ctx.SegSs = kernel::user_ds_selector;
	ctx.EFlags = 0x200;
	ctx.Rip = rtl_user_thread_start;
	ctx.Rsp = stack_top - 8;
	ctx.Rcx = entry_point;

	static_cast<void>(emulator->write_virtual_memory(context_address, &ctx, sizeof(ctx)));

	const emulator_t::address_type sentinel = emulator_t::thread_return_address;
	const emulator_t::address_type rsp = context_address - 8;

	static_cast<void>(emulator->write_virtual_memory(rsp, &sentinel, sizeof(sentinel)));

	auto& state = thread->state();
	state.rsp = rsp;
	state.rcx = context_address;
	state.rdx = context.ntdll_base;

	GLOBAL_LOG("created initial user thread (tid={}, ldr=0x{:X}, entry=0x{:X}, ctx=0x{:X}, teb=0x{:X})",
		thread->id(), ldr_initialize_thunk, entry_point, context_address, context.teb_address);

	return thread;
}

void user::initialize_system(const std::shared_ptr<emulator_t>& emulator,
	const std::shared_ptr<image_t>& nt_image)
{
	user::memory_manager = std::make_unique<user::memory_manager_t>(emulator);

	const std::filesystem::path vfs_dir("vfs");

	if (std::filesystem::exists(vfs_dir))
	{
		for (const auto& entry : std::filesystem::directory_iterator(vfs_dir))
		{
			if (!entry.is_regular_file())
			{
				continue;
			}

			const auto ext = entry.path().extension().string();

			if (ext != ".dll" && ext != ".DLL")
			{
				continue;
			}

			const auto filename = entry.path().filename().string();

			std::string lower_name(filename);

			for (auto& c : lower_name)
			{
				c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
			}

			const auto fs_path = "system32/" + lower_name;

			if (!kernel::filesystem->exists(fs_path))
			{
				kernel::filesystem->load_at(filename, fs_path);
			}
		}
	}

	user::ntdll_image = kernel::map_user_image(emulator, "ntdll.dll", false, true);

	if (!user::ntdll_image)
	{
		throw std::runtime_error("failed to load ntdll.dll for usermode emulation");
	}

	user::module_entries.push_back(user::ntdll_image);

	user::kernelbase_image = kernel::map_user_image(emulator, "kernelbase.dll", true, false, true);

	if (user::kernelbase_image)
	{
		user::module_entries.push_back(user::kernelbase_image);
		GLOBAL_LOG("usermode: loaded kernelbase.dll at 0x{:X}", user::kernelbase_image->base_address());
	}
	else
	{
		GLOBAL_WARN_LOG("usermode: kernelbase.dll not found in vfs/ - some imports may fail");
	}

	user::kernel32_image = kernel::map_user_image(emulator, "kernel32.dll", true, false, true);

	if (user::kernel32_image)
	{
		user::module_entries.push_back(user::kernel32_image);
		GLOBAL_LOG("usermode: loaded kernel32.dll at 0x{:X}", user::kernel32_image->base_address());
	}
	else
	{
		GLOBAL_WARN_LOG("usermode: kernel32.dll not found in vfs/ - some imports may fail");
	}

	user::win32u_image = kernel::map_user_image(emulator, "win32u.dll");

	user::syscall_table.parse_from_image(emulator, user::ntdll_image);

	if (user::win32u_image)
	{
		user::syscall_table.parse_from_image(emulator, user::win32u_image);
	}

	for (const auto& [name, address] : nt_image->symbols())
	{
		if (const auto handler = kernel::find_redirected_function(address))
		{
			user::syscall_table.register_handler(name, *handler);
		}
	}

	const auto win32k_image = kernel::find_module("win32k.sys");

	if (win32k_image)
	{
		redirect_win32k_user_functions(emulator, *win32k_image);

		for (const auto& [name, address] : win32k_image->symbols())
		{
			if (const auto handler = kernel::find_redirected_function(address))
			{
				user::syscall_table.register_handler(name, *handler);
			}
		}
	}

	redirect_ntoskrnl_syscall_handler(emulator, *nt_image);

	const auto ki_user_exception_disp = user::ntdll_image->find_symbol("KiUserExceptionDispatcher");

	if (ki_user_exception_disp)
	{
		user::ki_user_exception_dispatcher_address = *ki_user_exception_disp;
		GLOBAL_LOG("usermode: KiUserExceptionDispatcher at 0x{:X}", *ki_user_exception_disp);
	}
	else
	{
		GLOBAL_WARN_LOG("usermode: KiUserExceptionDispatcher not found in ntdll");
	}

	const auto ldr_init_thunk = user::ntdll_image->find_symbol("LdrInitializeThunk");
	const auto rtl_user_thread_start = user::ntdll_image->find_symbol("RtlUserThreadStart");

	if (!ldr_init_thunk || !rtl_user_thread_start)
	{
		throw std::runtime_error("usermode: LdrInitializeThunk or RtlUserThreadStart not found in ntdll");
	}

	user::ldr_initialize_thunk_address = *ldr_init_thunk;
	user::rtl_user_thread_start_address = *rtl_user_thread_start;

	GLOBAL_LOG("usermode system initialized: syscall stubs={}", user::syscall_table.size());
}

void user::create_user_process(const std::shared_ptr<emulator_t>& emulator,
	const std::string_view usermode_module_name)
{
	static bool first_process = true;

	std::shared_ptr<image_t> process_ntdll;
	std::shared_ptr<image_t> process_kernelbase;
	std::shared_ptr<image_t> process_kernel32;

	std::vector<std::shared_ptr<image_t>> saved_entries;

	if (first_process)
	{
		process_ntdll = user::ntdll_image;
		process_kernelbase = user::kernelbase_image;
		process_kernel32 = user::kernel32_image;
		first_process = false;
	}
	else
	{
		// each process needs its own system DLL copies so writable sections
		// (.data/.bss) are clean - ntdll's LdrpInitializeProcess skips heap
		// creation if it sees "already initialized" flags from another process
		saved_entries = user::module_entries;
		user::module_entries.clear();

		process_ntdll = kernel::map_user_image(emulator, "ntdll.dll", false, true);

		if (!process_ntdll)
		{
			throw std::runtime_error("failed to load ntdll.dll for process: " + std::string(usermode_module_name));
		}

		user::module_entries.push_back(process_ntdll);

		process_kernelbase = kernel::map_user_image(emulator, "kernelbase.dll", true, false, true);

		if (process_kernelbase)
		{
			user::module_entries.push_back(process_kernelbase);
		}

		process_kernel32 = kernel::map_user_image(emulator, "kernel32.dll", true, false, true);

		if (process_kernel32)
		{
			user::module_entries.push_back(process_kernel32);
		}

		GLOBAL_LOG("usermode: mapped per-process DLLs for {} (ntdll=0x{:X})",
			usermode_module_name, process_ntdll->base_address());
	}

	auto usermode_image = kernel::map_user_image(emulator, std::string(usermode_module_name), true, false, true);

	if (!usermode_image)
	{
		throw std::runtime_error("failed to load usermode target: " + std::string(usermode_module_name));
	}

	// merge saved entries back so find_module_from_rip can resolve all DLL instances
	for (auto& entry : saved_entries)
	{
		user::module_entries.push_back(std::move(entry));
	}

	// resolve per-process addresses from this process's ntdll
	const auto ldr_init_thunk = process_ntdll->find_symbol("LdrInitializeThunk");
	const auto rtl_user_thread_start = process_ntdll->find_symbol("RtlUserThreadStart");

	if (!ldr_init_thunk || !rtl_user_thread_start)
	{
		throw std::runtime_error("usermode: LdrInitializeThunk or RtlUserThreadStart not found in ntdll");
	}

	const auto process_id = kernel::object_manager->allocate_id();
	auto process = kernel::create_process(emulator, process_id,
		usermode_module_name, usermode_image->base_address(),
		[](const emulator_t::size_type size)
		{
			return user::memory_manager->allocate_pages(size);
		});

	if (const auto ki_disp = process_ntdll->find_symbol("KiUserExceptionDispatcher"))
	{
		process->set_ki_user_exception_dispatcher(*ki_disp);
	}

	std::vector<std::shared_ptr<image_t>> extra_modules;

	if (process_kernelbase)
	{
		extra_modules.push_back(process_kernelbase);
	}

	if (process_kernel32)
	{
		extra_modules.push_back(process_kernel32);
	}

	const auto um_context = user::set_up_structures(emulator,
		usermode_image->base_address(), process_ntdll->base_address(),
		usermode_image->size(), process_ntdll->size(),
		usermode_module_name, process, extra_modules);

	auto um_thread = user::create_initial_thread(emulator,
		usermode_image->entry_point(),
		*ldr_init_thunk,
		*rtl_user_thread_start,
		um_context, process);

	kernel::pending_threads.push(std::move(um_thread));

	GLOBAL_LOG("usermode: process created for {} (pid={}, base=0x{:X}, entry=0x{:X})",
		usermode_module_name, process_id, usermode_image->base_address(), usermode_image->entry_point());
}
