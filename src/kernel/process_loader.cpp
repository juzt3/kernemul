#include "process_loader.hpp"
#include "kernel.hpp"
#include "peb_layout.hpp"
#include "../emulator/object.hpp"

#include "../util/logs.hpp"

#include <cassert>

#include <format>

static emulator_t::address_type get_active_process_links_address(const process_t& process)
{
	return process.address() + offsetof(_EPROCESS, ActiveProcessLinks);
}

static void set_process_flink(const std::shared_ptr<emulator_t>& emulator,
	const process_t& process, const emulator_t::address_type flink)
{
	const auto links_address = get_active_process_links_address(process);

	const emulator_err_t error = emulator->write_virtual_memory(links_address, &flink, sizeof(flink));
	error.throw_if("write process Flink");
}

static void set_process_blink(const std::shared_ptr<emulator_t>& emulator,
	const process_t& process, const emulator_t::address_type blink)
{
	const auto links_address = get_active_process_links_address(process) + sizeof(emulator_t::address_type);

	const emulator_err_t error = emulator->write_virtual_memory(links_address, &blink, sizeof(blink));
	error.throw_if("write process Blink");
}

static void write_process_links(const std::shared_ptr<emulator_t>& emulator,
	const process_t& process,
	const emulator_t::address_type flink, const emulator_t::address_type blink)
{
	set_process_flink(emulator, process, flink);
	set_process_blink(emulator, process, blink);
}

void kernel::write_process_peb(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type peb_address,
	const peb_setup_options_t& options)
{
	peb64_t peb = { };

	peb.NumberOfProcessors = kernel::processor_count;

	peb.HeapSegmentReserve = 0x100000;
	peb.HeapSegmentCommit = 0x1000;
	peb.HeapDeCommitTotalFreeThreshold = 0x10000;
	peb.HeapDeCommitFreeBlockThreshold = 0x1000;
	peb.MaximumNumberOfHeaps = 0x10;

	peb.OSMajorVersion = 10;
	peb.OSBuildNumber = 19045;
	peb.OSPlatformId = 2;

	peb.ImageSubsystem = 3;
	peb.ImageSubsystemMajorVersion = 6;

	peb.ImageBaseAddress = options.image_base_address;
	peb.Ldr = options.ldr;
	peb.ProcessParameters = options.process_parameters;
	peb.ApiSetMap = options.api_set_map;
	peb.GdiSharedHandleTable = options.gdi_shared_handle_table;

	const emulator_err_t error = emulator->write_virtual_memory(peb_address, &peb, sizeof(peb));
	error.throw_if("write_process_peb");
}

void process_t::set_peb_address(const address_type addr)
{
	peb_address_ = addr;

	const auto peb_ptr = reinterpret_cast<_PEB*>(addr);
	const auto peb_field_address = object_.address() + offsetof(_EPROCESS, Peb);

	const emulator_err_t error = object_.get_emulator()->write_virtual_memory(
		peb_field_address, &peb_ptr, sizeof(peb_ptr));
	error.throw_if("process_t::set_peb_address: write _EPROCESS.Peb");
}

void kernel::set_up_initial_system_process(const std::shared_ptr<emulator_t>& emulator)
{
	const auto ntoskrnl = find_module("ntoskrnl.exe");

	if (!ntoskrnl)
	{
		throw std::runtime_error("unable to find ntoskrnl.exe");
	}

	const process_t::id_type system_process_id = object_manager->allocate_id();
	assert(system_process_id == 4 && "system process must be the first ID allocated");

	const auto system_process = create_process(emulator, system_process_id, "System", ntoskrnl->base_address());

	if (const auto symbol = ntoskrnl->find_symbol("PsInitialSystemProcess"))
	{
		const auto process_address = system_process->address();

		const emulator_err_t error = emulator->write_virtual_memory(*symbol, &process_address, sizeof(process_address));
		error.throw_if("write PsInitialSystemProcess");
	}

	static constexpr const char* fake_process_names[] = {
		"Registry",
		"smss.exe",
		"csrss.exe",
		"wininit.exe",
		"csrss.exe",
		"winlogon.exe",
		"services.exe",
		"lsass.exe",
		"svchost.exe",
		"svchost.exe",
		"svchost.exe",
		"svchost.exe",
		"svchost.exe",
		"svchost.exe",
		"svchost.exe",
		"svchost.exe",
		"fontdrvhost.ex",
		"fontdrvhost.ex",
		"dwm.exe",
		"svchost.exe",
		"svchost.exe",
		"svchost.exe",
		"svchost.exe",
		"svchost.exe",
		"svchost.exe",
		"svchost.exe",
		"WmiPrvSE.exe",
		"spoolsv.exe",
		"MsMpEng.exe",
		"NisSrv.exe",
		"SearchIndexer.",
		"explorer.exe",
		"RuntimeBroker.",
		"sihost.exe",
		"taskhostw.exe",
		"ctfmon.exe",
		"conhost.exe",
		"dllhost.exe",
		"SearchHost.exe",
		"StartMenuExper",
	};

	for (const auto* name : fake_process_names)
	{
		const auto pid = object_manager->allocate_id();
		create_process(emulator, pid, name, 0);
	}

	GLOBAL_LOG("populated {} fake system processes ({} total)",
		std::size(fake_process_names), process_entries.size());
}

std::shared_ptr<process_t> kernel::create_process(const std::shared_ptr<emulator_t>& emulator,
	const process_t::id_type process_id, const std::string_view image_name,
	const emulator_t::address_type section_base_address,
	const allocator_t& allocator)
{
	const auto object_name = std::format("EPROCESS_{}_{}", process_id, image_name);

	_EPROCESS contents = { };

	contents.UniqueProcessId = reinterpret_cast<void*>(process_id);
	contents.SectionBaseAddress = reinterpret_cast<void*>(section_base_address);

	constexpr std::size_t max_image_name = sizeof(contents.ImageFileName) - 1;
	const auto copy_length = std::min(image_name.size(), max_image_name);

	std::memcpy(contents.ImageFileName, image_name.data(), copy_length);

	const auto handle_table_address = emulator->heap_allocate(0x80, prot_read_write, true);

	if (handle_table_address)
	{
		contents.ObjectTable = reinterpret_cast<_HANDLE_TABLE*>(*handle_table_address);
	}

	const auto token_address = emulator->heap_allocate(0x100, prot_read_write, true);

	if (token_address)
	{
		contents.Token.Object = reinterpret_cast<void*>(*token_address);
	}

	auto object = emulator_object_t<_EPROCESS>::allocate(emulator, contents, object_name, true);

	auto process = std::make_shared<process_t>(process_id, section_base_address, std::move(object), std::string(image_name));
	process->set_handle_table(std::make_shared<handle_table_t>(emulator, object_manager));

	const auto peb_address = allocator
		? allocator(peb64_alloc_size)
		: emulator->heap_allocate(peb64_alloc_size, prot_read_write, true).value_or(0);

	if (peb_address)
	{
		write_process_peb(emulator, peb_address);
		process->set_peb_address(peb_address);
	}

	const auto self_links = get_active_process_links_address(*process);

	if (process_entries.empty())
	{
		write_process_links(emulator, *process, self_links, self_links);
	}
	else
	{
		auto& first = process_entries.front();
		auto& last = process_entries.back();

		const auto first_links = get_active_process_links_address(*first);
		const auto last_links = get_active_process_links_address(*last);

		write_process_links(emulator, *process, first_links, last_links);
		set_process_flink(emulator, *last, self_links);
		set_process_blink(emulator, *first, self_links);
	}

	// register in object manager so ObOpenObjectByPointer can create handles
	object_manager->register_object(process->address(), nullptr);

	GLOBAL_LOG("created process (process id={}, section base=0x{:X}, object address=0x{:X})",
		process_id, section_base_address, process->address());

	process_entries.push_back(process);

	for (const auto callback : kernel::process_create_notify_routines)
	{
		GLOBAL_LOG("invoking process notify routine (callback=0x{:X})", callback);

		std::vector<emulator_t::address_type> arguments = {};
		arguments.push_back(4); /* ParentId */
		arguments.push_back(process->id()); /* ProcessId */
		arguments.push_back(TRUE); /* Create */

		auto thread = kernel::create_thread_at(emulator, callback, arguments, 0, 0, process);
		kernel::pending_threads.push(thread);
	}

	for (const auto callback : kernel::process_create_notify_routines_ex)
	{
		GLOBAL_LOG("invoking process notify routine ex (callback=0x{:X})", callback);

		struct ps_create_notify_info
		{
			std::uint64_t size;
			std::uint32_t flags;
			std::uint32_t pad;
			std::uint64_t parent_process_id;
			std::uint64_t creating_thread_process_id;
			std::uint64_t creating_thread_thread_id;
			std::uint64_t file_object;
			std::uint64_t image_file_name;
			std::uint64_t command_line;
			std::uint32_t creation_status;
		};

		ps_create_notify_info info = {};
		info.size = sizeof(ps_create_notify_info);
		info.parent_process_id = 4;

		const auto info_obj = emulator_object_t<ps_create_notify_info>::allocate(emulator, info);

		std::vector<emulator_t::address_type> arguments = {};
		arguments.push_back(process->address()); /* Process (PEPROCESS) */
		arguments.push_back(process->id()); /* ProcessId */
		arguments.push_back(info_obj.address()); /* CreateInfo (PPS_CREATE_NOTIFY_INFO) */

		auto thread = kernel::create_thread_at(emulator, callback, arguments, 0, 0, process);
		kernel::pending_threads.push(thread);
	}

	return process;
}
