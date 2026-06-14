#include "process_loader.hpp"
#include "kernel.hpp"
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
	const emulator_t::address_type section_base_address)
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

	auto object = emulator_object_t<_EPROCESS>::allocate(emulator, contents, object_name);

	auto process = std::make_shared<process_t>(process_id, section_base_address, std::move(object), std::string(image_name));

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

	return process;
}
