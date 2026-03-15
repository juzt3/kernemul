#include "nt_helpers.hpp"
#include <Windows.h>

// todo: remove this once all needed classes are implemented
using nt_query_system_information_fn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

static nt_query_system_information_fn get_host_nt_query_system_information()
{
	static const auto fn = reinterpret_cast<nt_query_system_information_fn>(
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));

	return fn;
}

constexpr std::uint32_t status_info_length_mismatch = 0xC0000004;
constexpr std::uint32_t status_not_implemented = 0xC0000002;
constexpr std::uint32_t status_integer_overflow = 0xC0000095;

constexpr std::uint32_t system_module_information = 0x0B;
constexpr std::uint32_t system_module_information_ex = 0x4D;

struct rtl_process_module_information
{
	std::uint64_t section;
	std::uint64_t mapped_base;
	std::uint64_t image_base;
	std::uint32_t image_size;
	std::uint32_t flags;
	std::uint16_t load_order_index;
	std::uint16_t init_order_index;
	std::uint16_t load_count;
	std::uint16_t offset_to_file_name;
	std::uint8_t full_path_name[256];
};

struct rtl_process_module_information_ex
{
	std::uint16_t next_entry_offset;
	std::uint8_t padding[6];
	rtl_process_module_information base_info;
	std::uint32_t image_checksum;
	std::uint32_t time_date_stamp;
	std::uint64_t default_base;
};

static_assert(sizeof(rtl_process_module_information) == 0x128);
static_assert(sizeof(rtl_process_module_information_ex) == 0x140);

constexpr std::uint32_t module_entry_size = sizeof(rtl_process_module_information_ex);

struct rtl_process_modules
{
	std::uint32_t number_of_modules;
	std::uint32_t padding;
	rtl_process_module_information modules[1];
};

constexpr std::uint32_t module_info_entry_size = sizeof(rtl_process_module_information);
constexpr std::uint32_t module_info_header_size = 8;

static_assert(module_info_entry_size == 296);

static bool handle_system_module_information(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type buffer_address, const std::uint32_t buffer_length,
	const emulator_t::address_type return_length_address)
{
	const auto& modules = kernel::module_entries;
	const auto module_count = static_cast<std::uint32_t>(modules.size());
	const std::uint32_t required_size = module_info_header_size + module_count * module_info_entry_size;

	spdlog::info("NtQuerySystemInformation(0xB): {} modules, required_size=0x{:X}, buffer_length=0x{:X}",
		module_count, required_size, buffer_length);

	if (return_length_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			return_length_address, &required_size, sizeof(required_size));
		error.throw_if("write return length");
	}

	if (buffer_length < module_info_header_size)
	{
		write_nt_status(emulator, status_info_length_mismatch);
		return true;
	}

	std::vector<std::uint8_t> output(required_size, 0);
	auto* header = reinterpret_cast<rtl_process_modules*>(output.data());

	std::uint32_t entries_written = 0;
	std::uint32_t status = 0;

	for (std::uint32_t i = 0; i < module_count; ++i)
	{
		const auto current_required = module_info_header_size + (i + 1) * module_info_entry_size;

		if (buffer_length < current_required)
		{
			if (return_length_address)
			{
				emulator_err_t error = emulator->write_virtual_memory(
					return_length_address, &current_required, sizeof(current_required));
				error.throw_if("write return length on overflow");
			}

			status = status_info_length_mismatch;

			break;
		}

		const auto& module = modules[i];
		auto& entry = header->modules[i];

		entry.section = 0;
		entry.mapped_base = 0;
		entry.image_base = module->base_address();
		entry.image_size = static_cast<std::uint32_t>(module->size());
		entry.flags = 0;
		entry.load_order_index = static_cast<std::uint16_t>(i);
		entry.init_order_index = 0;
		entry.load_count = 1;

		const auto& name = module->name();
		const std::string full_path = "\\SystemRoot\\system32\\drivers\\" + name;

		const auto path_len = std::min(full_path.size(), static_cast<std::size_t>(255));
		std::memcpy(entry.full_path_name, full_path.data(), path_len);
		entry.full_path_name[path_len] = 0;

		const auto last_separator = full_path.rfind('\\');
		entry.offset_to_file_name = (last_separator != std::string::npos)
			? static_cast<std::uint16_t>(last_separator + 1)
			: 0;

		spdlog::info("  module[{}]: base=0x{:X}, size=0x{:X}, name='{}'",
			i, entry.image_base, entry.image_size,
			reinterpret_cast<const char*>(entry.full_path_name));

		++entries_written;
	}

	header->number_of_modules = entries_written;

	const auto write_size = std::min(required_size, buffer_length);

	if (write_size && buffer_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			buffer_address, output.data(), write_size);
		error.throw_if("write module information to guest");
	}

	write_nt_status(emulator, status);
	return true;
}

static void handle_query_system_information(const std::shared_ptr<emulator_t>& emulator)
{
	const auto info_class = emulator->read_register<x86::reg::rcx, std::uint32_t>();
	const auto buffer_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
	const auto buffer_length = emulator->read_register<x86::reg::r8, std::uint32_t>();
	const auto return_length_address = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

	spdlog::info("NtQuerySystemInformation called (class=0x{:X}, buffer=0x{:X}, length=0x{:X}, return_length=0x{:X})",
		info_class, buffer_address, buffer_length, return_length_address);

	// todo: implement needed classes and remove host passthrough
	const auto host_fn = get_host_nt_query_system_information();

	std::uint32_t status = status_not_implemented;

	if (!host_fn)
	{
		spdlog::warn("NtQuerySystemInformation: class 0x{:X}, host fallback unavailable", info_class);
	}
	else
	{
		spdlog::info("NtQuerySystemInformation: forwarding class 0x{:X} to host", info_class);

		std::vector<std::uint8_t> host_buffer(buffer_length);
		ULONG host_return_length = 0;

		status = static_cast<std::uint32_t>(host_fn(
			info_class, host_buffer.data(), buffer_length, &host_return_length));

		if (buffer_length && buffer_address)
		{
			if (const auto write_size = std::min(static_cast<std::uint32_t>(host_return_length), buffer_length))
			{
				emulator_err_t error = emulator->write_virtual_memory(
					buffer_address, host_buffer.data(), write_size);

				error.throw_if("write host query result to guest");
			}
		}

		if (return_length_address)
		{
			emulator_err_t error = emulator->write_virtual_memory(
				return_length_address, &host_return_length, sizeof(host_return_length));

			error.throw_if("write host return length to guest");
		}

		spdlog::info("NtQuerySystemInformation: host returned 0x{:X} (return_length=0x{:X})",
			status, host_return_length);

		if (info_class == system_module_information_ex && status == 0 && host_return_length >= sizeof(std::uint16_t))
		{
			auto* entry = reinterpret_cast<rtl_process_module_information_ex*>(host_buffer.data());
			std::uint16_t index = 0;

			while (entry->next_entry_offset != 0)
			{
				const auto* file_name = reinterpret_cast<const char*>(
					&entry->base_info.full_path_name[entry->base_info.offset_to_file_name]);

				for (const auto& module : kernel::module_entries)
				{
					if (_stricmp(file_name, module->name().c_str()) == 0)
					{
						spdlog::info("  host module[{}]: '{}' base remapped 0x{:X} -> 0x{:X}",
							index, file_name, entry->base_info.image_base, module->base_address());

						entry->base_info.image_base = module->base_address();
						entry->base_info.image_size = static_cast<std::uint32_t>(module->size());
						break;
					}
				}

				spdlog::info("  host module[{}]: base=0x{:X}, size=0x{:X}, name='{}'",
					index,
					entry->base_info.image_base,
					entry->base_info.image_size,
					reinterpret_cast<const char*>(entry->base_info.full_path_name));

				entry = reinterpret_cast<rtl_process_module_information_ex*>(
					reinterpret_cast<std::uint8_t*>(entry) + entry->next_entry_offset);

				++index;
			}

			spdlog::info("  host module count: {}", index);

			const auto write_size = std::min(static_cast<std::uint32_t>(host_return_length), buffer_length);

			if (write_size && buffer_address)
			{
				emulator_err_t error = emulator->write_virtual_memory(
					buffer_address, host_buffer.data(), write_size);

				error.throw_if("write fixedup host query result to guest");
			}

			auto buf_addr = buffer_address;
			auto buf_size = static_cast<emulator_t::address_type>(write_size);

			emulator->hook_memory(
				[buf_addr, buf_size](emulator_t::address_type address, emulator_t::protection_type)
				{
					const auto offset_in_buffer = address - buf_addr;
					const auto entry_index = offset_in_buffer / module_entry_size;
					const auto offset_in_entry = offset_in_buffer % module_entry_size;

					constexpr auto full_path_offset = offsetof(rtl_process_module_information_ex, base_info)
						+ offsetof(rtl_process_module_information, full_path_name);
					constexpr auto image_base_offset = offsetof(rtl_process_module_information_ex, base_info)
						+ offsetof(rtl_process_module_information, image_base);

					if (offset_in_entry >= full_path_offset && offset_in_entry < full_path_offset + 256)
					{
						spdlog::info("  [monitor] guest reading full_path_name of module[{}] at 0x{:X}",
							entry_index, address);
					}
					else if (offset_in_entry >= image_base_offset && offset_in_entry < image_base_offset + 8)
					{
						spdlog::info("  [monitor] guest reading image_base of module[{}] at 0x{:X}",
							entry_index, address);
					}
				},
				prot_read,
				buffer_address,
				buffer_address + buf_size
			);
		}

		if (info_class == system_module_information && status == 0 && host_return_length >= module_info_header_size)
		{
			auto* header = reinterpret_cast<rtl_process_modules*>(host_buffer.data());
			const auto count = header->number_of_modules;

			for (std::uint32_t i = 0; i < count; ++i)
			{
				auto& entry = header->modules[i];

				const auto* file_name = reinterpret_cast<const char*>(
					&entry.full_path_name[entry.offset_to_file_name]);

				for (const auto& module : kernel::module_entries)
				{
					if (_stricmp(file_name, module->name().c_str()) == 0)
					{
						spdlog::info("  host module[{}]: '{}' base remapped 0x{:X} -> 0x{:X}",
							i, file_name, entry.image_base, module->base_address());

						entry.image_base = module->base_address();
						entry.image_size = static_cast<std::uint32_t>(module->size());
						break;
					}
				}

				spdlog::info("  host module[{}]: base=0x{:X}, size=0x{:X}, name='{}'",
					i, entry.image_base, entry.image_size,
					reinterpret_cast<const char*>(entry.full_path_name));
			}

			spdlog::info("  host module count (0xB): {}", count);

			const auto write_size = std::min(static_cast<std::uint32_t>(host_return_length), buffer_length);

			if (write_size && buffer_address)
			{
				emulator_err_t error = emulator->write_virtual_memory(
					buffer_address, host_buffer.data(), write_size);

				error.throw_if("write fixedup host 0xB result to guest");
			}
		}
	}

	if (status == status_info_length_mismatch && return_length_address)
	{
		std::uint32_t returned_length = 0;

		emulator_err_t error = emulator->read_virtual_memory(return_length_address, &returned_length, sizeof(returned_length));

		error.throw_if("read return length for logging");

		spdlog::info("NtQuerySystemInformation returning 0x{:X} (required_size=0x{:X})", status, returned_length);
	}
	else
	{
		spdlog::info("NtQuerySystemInformation returning 0x{:X}", status);
	}

	write_nt_status(emulator, status);
}

void redirect_ntoskrnl_sysinfo_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image)
{
	redirect_function(
		[emulator] { handle_query_system_information(emulator); },
		mapped_image,
		"NtQuerySystemInformation"
	);

	redirect_function(
		[emulator] { handle_query_system_information(emulator); },
		mapped_image,
		"ZwQuerySystemInformation"
	);
}
