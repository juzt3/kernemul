#include "process_loader.hpp"
#include "kernel.hpp"
#include "../emulator/object.hpp"

#include <spdlog/spdlog.h>

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

	constexpr process_t::id_type system_process_id = 4;

	// todo: check image file name for system process (id=4)
	const auto system_process = create_process(emulator, system_process_id, "System", ntoskrnl->base_address());

	if (const auto symbol = ntoskrnl->find_symbol("PsInitialSystemProcess"))
	{
		const auto process_address = system_process->address();

		const emulator_err_t error = emulator->write_virtual_memory(*symbol, &process_address, sizeof(process_address));
		error.throw_if("write PsInitialSystemProcess");
	}
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

	auto object = emulator_object_t<_EPROCESS>::allocate(emulator, contents, object_name);

	auto process = std::make_shared<process_t>(process_id, section_base_address, std::move(object));

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

	spdlog::info("created process (process id={}, section base=0x{:X}, object address=0x{:X})",
		process_id, section_base_address, process->address());

	process_entries.push_back(process);

	return process;
}
