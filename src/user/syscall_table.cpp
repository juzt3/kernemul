#include "syscall_table.hpp"

#include "../util/logs.hpp"

#include <cstring>

void user::syscall_table_t::parse_from_image(const std::shared_ptr<emulator_t>& emulator,
	const std::shared_ptr<image_t>& image)
{
	const auto buffer = image->buffer();
	const auto base = image->base_address();
	std::size_t count = 0;

	for (const auto& [name, address] : image->symbols())
	{
		const auto rva = address - base;

		if (rva + 8 > buffer.size())
		{
			continue;
		}

		const auto* bytes = buffer.data() + rva;

		// syscall stub pattern (ntdll and win32u):
		//   4C 8B D1       mov r10, rcx
		//   B8 XX XX XX XX mov eax, syscall_number
		if (bytes[0] != 0x4C || bytes[1] != 0x8B || bytes[2] != 0xD1)
		{
			continue;
		}

		if (bytes[3] != 0xB8)
		{
			continue;
		}

		syscall_id_type syscall_number = 0;
		std::memcpy(&syscall_number, bytes + 4, sizeof(syscall_number));

		name_to_number_[name] = syscall_number;

		entries_[syscall_number] = syscall_entry_t
		{
			.number = syscall_number,
			.name = name,
			.handler = {}
		};

		++count;
	}

	GLOBAL_LOG("parsed syscall stubs from {}: {} found (total {})",
		image->name(), count, entries_.size());
}

void user::syscall_table_t::register_handler(const std::string& name,
	const kernel::function_implementation_t& handler)
{
	const auto it = name_to_number_.find(name);

	if (it == name_to_number_.end())
	{
		//GLOBAL_WARN_LOG("syscall_table: no stub found for '{}'", name);
		return;
	}

	const auto number = it->second;

	auto& entry = entries_[number];
	entry.handler = handler;

	//GLOBAL_LOG("registered syscall handler: {} -> #{}", name, number);
}

std::optional<user::syscall_entry_t> user::syscall_table_t::find_by_number(
	const syscall_id_type syscall_number) const
{
	const auto it = entries_.find(syscall_number);

	if (it != entries_.end() && it->second.handler)
	{
		return it->second;
	}

	return std::nullopt;
}

std::string_view user::syscall_table_t::find_name(const syscall_id_type syscall_number) const
{
	const auto it = entries_.find(syscall_number);

	if (it != entries_.end())
	{
		return it->second.name;
	}

	return {};
}
