#include "nt_helpers.hpp"
#include "../../kernel/process_loader.hpp"
#include <Windows.h>

// todo: remove this once all needed classes are implemented
using nt_query_system_information_fn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using nt_query_system_information_ex_fn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);

static nt_query_system_information_fn get_host_nt_query_system_information()
{
	static const auto fn = reinterpret_cast<nt_query_system_information_fn>(
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));

	return fn;
}

static nt_query_system_information_ex_fn get_host_nt_query_system_information_ex()
{
	static const auto fn = reinterpret_cast<nt_query_system_information_ex_fn>(
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformationEx"));

	return fn;
}

constexpr std::uint32_t status_info_length_mismatch = 0xC0000004;
constexpr std::uint32_t status_not_implemented = 0xC0000002;
constexpr std::uint32_t status_integer_overflow = 0xC0000095;
constexpr std::uint32_t status_success = 0x00000000;

constexpr std::uint32_t system_process_information = 0x05;
constexpr std::uint32_t system_basic_information = 0x00;
constexpr std::uint32_t system_emulation_basic_information = 0x3E;
constexpr std::uint32_t system_module_information = 0x0B;
constexpr std::uint32_t system_handle_information = 0x10;
constexpr std::uint32_t system_page_file_information = 0x12;
constexpr std::uint32_t system_pool_tag_information = 0x16;
constexpr std::uint32_t system_kernel_debugger_information = 0x23;
constexpr std::uint32_t system_kernel_debugger_information_ex = 0x42;
constexpr std::uint32_t system_code_integrity_information = 0x67;
constexpr std::uint32_t system_module_information_ex = 0x4D;
constexpr std::uint32_t system_code_integrity_policy_information = 0x5A;
constexpr std::uint32_t system_secure_speculation_control = 0x91;

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

#pragma pack(push, 8)
struct system_process_information_entry
{
	std::uint32_t next_entry_offset;
	std::uint32_t number_of_threads;
	LARGE_INTEGER spare_li[3];
	LARGE_INTEGER create_time;
	LARGE_INTEGER user_time;
	LARGE_INTEGER kernel_time;
	UNICODE_STRING image_name;
	std::int32_t base_priority;
	std::uint64_t unique_process_id;
	std::uint64_t inherited_from_unique_process_id;
	std::uint32_t handle_count;
	std::uint32_t session_id;
	std::uint64_t unique_process_key;
	std::uint64_t peak_virtual_size;
	std::uint64_t virtual_size;
	std::uint32_t page_fault_count;
	std::uint32_t padding1;
	std::uint64_t peak_working_set_size;
	std::uint64_t working_set_size;
	std::uint64_t quota_peak_paged_pool_usage;
	std::uint64_t quota_paged_pool_usage;
	std::uint64_t quota_peak_non_paged_pool_usage;
	std::uint64_t quota_non_paged_pool_usage;
	std::uint64_t pagefile_usage;
	std::uint64_t peak_pagefile_usage;
	std::uint64_t private_page_count;
	LARGE_INTEGER read_operation_count;
	LARGE_INTEGER write_operation_count;
	LARGE_INTEGER other_operation_count;
	LARGE_INTEGER read_transfer_count;
	LARGE_INTEGER write_transfer_count;
	LARGE_INTEGER other_transfer_count;
};
#pragma pack(pop)

struct system_thread_information
{
	LARGE_INTEGER kernel_time;
	LARGE_INTEGER user_time;
	LARGE_INTEGER create_time;
	std::uint32_t wait_time;
	std::uint32_t padding0;
	std::uint64_t start_address;
	std::uint64_t unique_process_id;
	std::uint64_t unique_thread_id;
	std::int32_t priority;
	std::int32_t base_priority;
	std::uint32_t context_switches;
	std::uint32_t thread_state;
	std::uint32_t wait_reason;
	std::uint32_t padding1;
};

static bool handle_system_process_information(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type buffer_address, const std::uint32_t buffer_length,
	const emulator_t::address_type return_length_address)
{
	const auto& processes = kernel::process_entries;

	// calculate required size - each process entry + one thread per process
	constexpr auto entry_size = sizeof(system_process_information_entry);
	constexpr auto thread_size = sizeof(system_thread_information);

	// we need space for each process entry + 1 thread info each + image name strings
	std::uint32_t required_size = 0;

	for (const auto& proc : processes)
	{
		// entry + 1 thread + space for image name (wide string, aligned to 8 bytes)
		const auto name_len = proc->name().size() * sizeof(wchar_t);
		const auto aligned_name = (name_len + 7) & ~static_cast<std::size_t>(7);
		required_size += static_cast<std::uint32_t>(entry_size + thread_size + aligned_name);
	}

	THREAD_LOG("NtQuerySystemInformation(0x5): {} processes, required_size=0x{:X}, buffer_length=0x{:X}",
		processes.size(), required_size, buffer_length);

	if (return_length_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			return_length_address, &required_size, sizeof(required_size));
		error.throw_if("write return length");
	}

	if (buffer_length < required_size)
	{
		write_nt_status(emulator, status_info_length_mismatch);
		return true;
	}

	std::vector<std::uint8_t> output(required_size, 0);
	std::uint32_t offset = 0;

	for (std::size_t i = 0; i < processes.size(); ++i)
	{
		const auto& proc = processes[i];
		auto* entry = reinterpret_cast<system_process_information_entry*>(output.data() + offset);
		auto* thread_info = reinterpret_cast<system_thread_information*>(output.data() + offset + entry_size);

		// convert name to wide string
		const auto& name = proc->name();
		const auto wide_name = util::widen_string(name);
		const auto name_bytes = wide_name.size() * sizeof(wchar_t);
		const auto aligned_name = (name_bytes + 7) & ~static_cast<std::size_t>(7);

		const auto this_entry_total = static_cast<std::uint32_t>(entry_size + thread_size + aligned_name);

		entry->unique_process_id = proc->id();
		entry->inherited_from_unique_process_id = 0;
		entry->handle_count = 32;
		entry->session_id = 0;
		entry->base_priority = 8;
		entry->number_of_threads = 1;
		entry->working_set_size = 0x100000;
		entry->virtual_size = 0x1000000;

		// image name string is placed after the thread info
		const auto string_offset = offset + static_cast<std::uint32_t>(entry_size + thread_size);
		std::memcpy(output.data() + string_offset, wide_name.data(), name_bytes);

		// the UNICODE_STRING in the entry needs a guest-relative buffer pointer
		entry->image_name.Length = static_cast<USHORT>(name_bytes);
		entry->image_name.MaximumLength = static_cast<USHORT>(name_bytes + sizeof(wchar_t));
		entry->image_name.Buffer = reinterpret_cast<PWSTR>(buffer_address + string_offset);

		// thread info
		thread_info->unique_process_id = proc->id();
		thread_info->unique_thread_id = proc->id() + 1;
		thread_info->priority = 8;
		thread_info->base_priority = 8;
		thread_info->thread_state = 5; // waiting
		thread_info->wait_reason = 13; // executive

		if (i + 1 < processes.size())
		{
			entry->next_entry_offset = this_entry_total;
		}
		else
		{
			entry->next_entry_offset = 0; // last entry
		}

		THREAD_LOG("  process[{}]: pid={}, name='{}', next_offset=0x{:X}",
			i, proc->id(), name, entry->next_entry_offset);

		offset += this_entry_total;
	}

	if (buffer_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			buffer_address, output.data(), required_size);
		error.throw_if("write process information to guest");
	}

	write_nt_status(emulator, status_success);
	return true;
}

static bool handle_system_module_information(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type buffer_address, const std::uint32_t buffer_length,
	const emulator_t::address_type return_length_address)
{
	const auto& modules = kernel::module_entries;
	const auto module_count = static_cast<std::uint32_t>(modules.size());
	const std::uint32_t required_size = module_info_header_size + module_count * module_info_entry_size;

	THREAD_LOG("NtQuerySystemInformation(0xB): {} modules, required_size=0x{:X}, buffer_length=0x{:X}",
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

		THREAD_LOG("  module[{}]: base=0x{:X}, size=0x{:X}, name='{}'",
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

static void fixup_module_information_ex(const std::shared_ptr<emulator_t>& emulator,
	std::vector<std::uint8_t>& host_buffer, const std::uint32_t host_return_length,
	const emulator_t::address_type buffer_address, const std::uint32_t buffer_length,
	const char* caller_name)
{
	if (host_return_length < sizeof(std::uint16_t))
	{
		return;
	}

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
				THREAD_LOG("  host module[{}]: '{}' base remapped 0x{:X} -> 0x{:X}",
					index, file_name, entry->base_info.image_base, module->base_address());

				entry->base_info.image_base = module->base_address();
				entry->base_info.image_size = static_cast<std::uint32_t>(module->size());
				break;
			}
		}

		THREAD_LOG("  host module[{}]: base=0x{:X}, size=0x{:X}, name='{}'",
			index,
			entry->base_info.image_base,
			entry->base_info.image_size,
			reinterpret_cast<const char*>(entry->base_info.full_path_name));

		entry = reinterpret_cast<rtl_process_module_information_ex*>(
			reinterpret_cast<std::uint8_t*>(entry) + entry->next_entry_offset);

		++index;
	}

	THREAD_LOG("  host module count: {}", index);

	const auto write_size = std::min(host_return_length, buffer_length);

	if (write_size && buffer_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			buffer_address, host_buffer.data(), write_size);

		error.throw_if("write fixedup host query result to guest");
	}

	auto buf_addr = buffer_address;
	auto buf_size = static_cast<emulator_t::address_type>(write_size);
	std::string source(caller_name);

	emulator->hook_memory(
		[buf_addr, buf_size, source](emulator_t::address_type address, emulator_t::protection_type)
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
				THREAD_LOG("  [monitor:{}] guest reading full_path_name of module[{}] at 0x{:X}",
					source, entry_index, address);
			}
			else if (offset_in_entry >= image_base_offset && offset_in_entry < image_base_offset + 8)
			{
				THREAD_LOG("  [monitor:{}] guest reading image_base of module[{}] at 0x{:X}",
					source, entry_index, address);
			}
		},
		prot_read,
		buffer_address,
		buffer_address + buf_size
	);
}

static void fixup_module_information(const std::shared_ptr<emulator_t>& emulator,
	std::vector<std::uint8_t>& host_buffer, const std::uint32_t host_return_length,
	const emulator_t::address_type buffer_address, const std::uint32_t buffer_length)
{
	if (host_return_length < module_info_header_size)
	{
		return;
	}

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
				THREAD_LOG("  host module[{}]: '{}' base remapped 0x{:X} -> 0x{:X}",
					i, file_name, entry.image_base, module->base_address());

				entry.image_base = module->base_address();
				entry.image_size = static_cast<std::uint32_t>(module->size());
				break;
			}
		}

		THREAD_LOG("  host module[{}]: base=0x{:X}, size=0x{:X}, name='{}'",
			i, entry.image_base, entry.image_size,
			reinterpret_cast<const char*>(entry.full_path_name));
	}

	THREAD_LOG("  host module count (0xB): {}", count);

	const auto write_size = std::min(host_return_length, buffer_length);

	if (write_size && buffer_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			buffer_address, host_buffer.data(), write_size);

		error.throw_if("write fixedup host 0xB result to guest");
	}
}

static bool handle_system_handle_information(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type buffer_address, const std::uint32_t buffer_length,
	const emulator_t::address_type return_length_address)
{
	// return an empty handle table - no handles in the system
	// real structure: ULONG NumberOfHandles + SYSTEM_HANDLE_TABLE_ENTRY_INFO[]
	constexpr std::uint32_t header_size = sizeof(std::uint32_t);

	THREAD_LOG("NtQuerySystemInformation(0x10): returning empty handle table");

	if (return_length_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			return_length_address, &header_size, sizeof(header_size));
		error.throw_if("write return length");
	}

	if (buffer_length < header_size)
	{
		write_nt_status(emulator, status_info_length_mismatch);
		return true;
	}

	constexpr std::uint32_t zero_handles = 0;
	if (buffer_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			buffer_address, &zero_handles, sizeof(zero_handles));
		error.throw_if("write handle count");
	}

	write_nt_status(emulator, status_success);
	return true;
}

static bool handle_system_kernel_debugger_information(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type buffer_address, const std::uint32_t buffer_length,
	const emulator_t::address_type return_length_address, const std::uint32_t info_class)
{
	// SYSTEM_KERNEL_DEBUGGER_INFORMATION: { BOOLEAN DebuggerEnabled, BOOLEAN DebuggerNotPresent }
	// SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX: { BOOLEAN DebuggerAllowed, BOOLEAN DebuggerEnabled, BOOLEAN DebuggerPresent }

	if (info_class == system_kernel_debugger_information)
	{
		constexpr std::uint32_t required = 2;

		THREAD_LOG("NtQuerySystemInformation(0x23): returning no debugger");

		if (return_length_address)
		{
			emulator_err_t error = emulator->write_virtual_memory(
				return_length_address, &required, sizeof(required));
			error.throw_if("write return length");
		}

		if (buffer_length < required)
		{
			write_nt_status(emulator, status_info_length_mismatch);
			return true;
		}

		// DebuggerEnabled=FALSE, DebuggerNotPresent=TRUE
		const std::uint8_t data[2] = { 0, 1 };
		if (buffer_address)
		{
			emulator_err_t error = emulator->write_virtual_memory(
				buffer_address, &data, sizeof(data));
			error.throw_if("write debugger info");
		}

		write_nt_status(emulator, status_success);
		return true;
	}

	// system_kernel_debugger_information_ex (0x42)
	constexpr std::uint32_t required = 3;

	THREAD_LOG("NtQuerySystemInformation(0x42): returning no debugger (ex)");

	if (return_length_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			return_length_address, &required, sizeof(required));
		error.throw_if("write return length");
	}

	if (buffer_length < required)
	{
		write_nt_status(emulator, status_info_length_mismatch);
		return true;
	}

	// DebuggerAllowed=TRUE, DebuggerEnabled=FALSE, DebuggerPresent=FALSE
	const std::uint8_t data[3] = { 1, 0, 0 };
	if (buffer_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			buffer_address, &data, sizeof(data));
		error.throw_if("write debugger info ex");
	}

	write_nt_status(emulator, status_success);
	return true;
}

static bool handle_system_code_integrity_information(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type buffer_address, const std::uint32_t buffer_length,
	const emulator_t::address_type return_length_address)
{
	// SYSTEM_CODEINTEGRITY_INFORMATION: { ULONG Length, ULONG CodeIntegrityOptions }
	constexpr std::uint32_t required = 8;

	THREAD_LOG("NtQuerySystemInformation(0x67): returning code integrity enabled");

	if (return_length_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			return_length_address, &required, sizeof(required));
		error.throw_if("write return length");
	}

	if (buffer_length < required)
	{
		write_nt_status(emulator, status_info_length_mismatch);
		return true;
	}

	struct
	{
		std::uint32_t length;
		std::uint32_t code_integrity_options;
	} info = {};

	info.length = required;
	// CODEINTEGRITY_OPTION_ENABLED | CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
	info.code_integrity_options = 0x01 | 0x400;

	if (buffer_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			buffer_address, &info, sizeof(info));
		error.throw_if("write code integrity info");
	}

	write_nt_status(emulator, status_success);
	return true;
}

static bool handle_system_code_integrity_policy(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type buffer_address, const std::uint32_t buffer_length,
	const emulator_t::address_type return_length_address)
{
	THREAD_LOG("NtQuerySystemInformation(0x5A): returning STATUS_NOT_IMPLEMENTED for CI policy");

	if (return_length_address)
	{
		constexpr std::uint32_t zero = 0;
		static_cast<void>(emulator->write_virtual_memory(
			return_length_address, &zero, sizeof(zero)));
	}

	write_nt_status(emulator, status_not_implemented);
	return true;
}

static bool handle_system_page_file_information(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type buffer_address, const std::uint32_t buffer_length,
	const emulator_t::address_type return_length_address)
{
	// return empty - no page files (or a minimal one)
	// the structure has NextEntryOffset as first field; 0 means last entry
	constexpr std::uint32_t required = 0x20;

	THREAD_LOG("NtQuerySystemInformation(0x12): returning minimal pagefile info");

	if (return_length_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			return_length_address, &required, sizeof(required));
		error.throw_if("write return length");
	}

	if (buffer_length < required)
	{
		write_nt_status(emulator, status_info_length_mismatch);
		return true;
	}

	// SYSTEM_PAGEFILE_INFORMATION
	struct
	{
		std::uint32_t next_entry_offset;
		std::uint32_t total_size;
		std::uint32_t total_in_use;
		std::uint32_t peak_usage;
		UNICODE_STRING page_file_name;
	} info = {};

	info.next_entry_offset = 0;
	info.total_size = 4096; // ~16GB in pages
	info.total_in_use = 1024;
	info.peak_usage = 2048;

	if (buffer_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			buffer_address, &info, sizeof(info));
		error.throw_if("write pagefile info");
	}

	write_nt_status(emulator, status_success);
	return true;
}

static bool handle_system_pool_tag_information(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type buffer_address, const std::uint32_t buffer_length,
	const emulator_t::address_type return_length_address)
{
	// return a minimal set of realistic pool tags
	struct pool_tag_info
	{
		char tag[4];
		std::uint32_t paged_allocs;
		std::uint32_t paged_frees;
		std::uint64_t paged_used;
		std::uint32_t non_paged_allocs;
		std::uint32_t non_paged_frees;
		std::uint64_t non_paged_used;
	};

	static constexpr pool_tag_info fake_tags[] = {
		{ { 'C', 'M', '2', '5' }, 128, 64, 0x10000, 256, 128, 0x20000 },
		{ { 'N', 't', 'F', 's' }, 512, 256, 0x40000, 1024, 512, 0x80000 },
		{ { 'M', 'm', 'S', 't' }, 64, 32, 0x8000, 128, 64, 0x10000 },
		{ { 'P', 'o', 'o', 'l' }, 256, 128, 0x20000, 512, 256, 0x40000 },
		{ { 'T', 'h', 'r', 'd' }, 1024, 512, 0x80000, 2048, 1024, 0x100000 },
		{ { 'F', 'i', 'l', 'e' }, 2048, 1024, 0x100000, 4096, 2048, 0x200000 },
		{ { 'O', 'b', 'j', 'T' }, 512, 256, 0x40000, 1024, 512, 0x80000 },
		{ { 'I', 'r', 'p', ' ' }, 4096, 2048, 0x200000, 8192, 4096, 0x400000 },
	};

	constexpr std::uint32_t tag_count = static_cast<std::uint32_t>(std::size(fake_tags));
	constexpr std::uint32_t required = sizeof(std::uint32_t) + tag_count * sizeof(pool_tag_info);

	THREAD_LOG("NtQuerySystemInformation(0x16): returning {} fake pool tags", tag_count);

	if (return_length_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			return_length_address, &required, sizeof(required));
		error.throw_if("write return length");
	}

	if (buffer_length < required)
	{
		write_nt_status(emulator, status_info_length_mismatch);
		return true;
	}

	std::vector<std::uint8_t> output(required, 0);
	std::memcpy(output.data(), &tag_count, sizeof(tag_count));
	std::memcpy(output.data() + sizeof(std::uint32_t), fake_tags, sizeof(fake_tags));

	if (buffer_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			buffer_address, output.data(), required);
		error.throw_if("write pool tag information");
	}

	write_nt_status(emulator, status_success);
	return true;
}

static bool handle_system_secure_speculation_control(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type buffer_address, const std::uint32_t buffer_length,
	const emulator_t::address_type return_length_address)
{
	// return flags indicating mitigations are enabled
	constexpr std::uint32_t required = 4;

	THREAD_LOG("NtQuerySystemInformation(0x91): returning speculation control flags");

	if (return_length_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			return_length_address, &required, sizeof(required));
		error.throw_if("write return length");
	}

	if (buffer_length < required)
	{
		write_nt_status(emulator, status_info_length_mismatch);
		return true;
	}

	constexpr std::uint32_t flags = 0x3F; // all mitigations enabled
	if (buffer_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(
			buffer_address, &flags, sizeof(flags));
		error.throw_if("write speculation control flags");
	}

	write_nt_status(emulator, status_success);
	return true;
}

static void handle_query_system_information(const std::shared_ptr<emulator_t>& emulator,
	std::uint32_t info_class, emulator_t::address_type buffer_address,
	std::uint32_t buffer_length, emulator_t::address_type return_length_address)
{
	THREAD_LOG("NtQuerySystemInformation called (class=0x{:X}, buffer=0x{:X}, length=0x{:X}, return_length=0x{:X})",
		info_class, buffer_address, buffer_length, return_length_address);

	// SystemBasicInformation / SystemEmulationBasicInformation - hardcoded like sogen
	if (info_class == system_basic_information || info_class == system_emulation_basic_information)
	{
		struct system_basic_info
		{
			std::uint32_t reserved;
			std::uint32_t timer_resolution;
			std::uint32_t page_size;
			std::uint32_t number_of_physical_pages;
			std::uint32_t lowest_physical_page_number;
			std::uint32_t highest_physical_page_number;
			std::uint32_t allocation_granularity;
			std::uint64_t minimum_user_mode_address;
			std::uint64_t maximum_user_mode_address;
			std::uint64_t active_processors_affinity_mask;
			std::uint8_t number_of_processors;
		};

		constexpr std::uint32_t required_size = 0x40;
		if (buffer_length < required_size)
		{
			if (return_length_address)
			{
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &required_size, sizeof(required_size)));
			}
			write_nt_status(emulator, status_info_length_mismatch);
			return;
		}

		std::array<std::uint8_t, required_size> buf{};
		auto& info = *reinterpret_cast<system_basic_info*>(buf.data());
		info.reserved = 0;
		info.timer_resolution = 0x0002625A;
		info.page_size = 0x1000;
		info.number_of_physical_pages = 0;
		info.lowest_physical_page_number = 0x00000001;
		info.highest_physical_page_number = 0x00C9C7FF;
		info.allocation_granularity = 0x10000;
		info.minimum_user_mode_address = 0x10000;
		info.maximum_user_mode_address = 0x7FFFFFFEFFFF;
		info.active_processors_affinity_mask = 0x0F;
		info.number_of_processors = 4;

		static_cast<void>(emulator->write_virtual_memory(buffer_address, buf.data(), required_size));
		if (return_length_address)
		{
			static_cast<void>(emulator->write_virtual_memory(return_length_address, &required_size, sizeof(required_size)));
		}
		THREAD_LOG("NtQuerySystemInformation: SystemBasicInformation -> hardcoded (MaxUserAddr=0x7FFFFFFEFFFF, Processors=4)");
		write_nt_status(emulator, status_success);
		return;
	}

	// handle classes we can serve from emulated state
	if (info_class == system_module_information)
	{
		if (handle_system_module_information(emulator, buffer_address, buffer_length, return_length_address))
		{
			return;
		}
	}

	if (info_class == system_process_information)
	{
		if (handle_system_process_information(emulator, buffer_address, buffer_length, return_length_address))
		{
			return;
		}
	}

	if (info_class == system_handle_information)
	{
		if (handle_system_handle_information(emulator, buffer_address, buffer_length, return_length_address))
		{
			return;
		}
	}

	if (info_class == system_kernel_debugger_information || info_class == system_kernel_debugger_information_ex)
	{
		if (handle_system_kernel_debugger_information(emulator, buffer_address, buffer_length, return_length_address, info_class))
		{
			return;
		}
	}

	if (info_class == system_code_integrity_information)
	{
		if (handle_system_code_integrity_information(emulator, buffer_address, buffer_length, return_length_address))
		{
			return;
		}
	}

	if (info_class == system_code_integrity_policy_information)
	{
		if (handle_system_code_integrity_policy(emulator, buffer_address, buffer_length, return_length_address))
		{
			return;
		}
	}

	if (info_class == system_page_file_information)
	{
		if (handle_system_page_file_information(emulator, buffer_address, buffer_length, return_length_address))
		{
			return;
		}
	}

	if (info_class == system_pool_tag_information)
	{
		if (handle_system_pool_tag_information(emulator, buffer_address, buffer_length, return_length_address))
		{
			return;
		}
	}

	if (info_class == system_secure_speculation_control)
	{
		if (handle_system_secure_speculation_control(emulator, buffer_address, buffer_length, return_length_address))
		{
			return;
		}
	}

	// SystemNumaProcessorMap (0x37) - SYSTEM_NUMA_INFORMATION64
	// Layout: HighestNodeNumber (ULONG) + Reserved (ULONG) + union of arrays[MAXIMUM_NODE_COUNT=64]
	// Union: GROUP_AFFINITY[64] (each 16 bytes) / ULONGLONG AvailableMemory[64] / ULONGLONG Pad[128]
	// Total size: 8 + max(64*16, 64*8, 128*8) = 8 + 1024 = 0x408
	if (info_class == 0x37)
	{
		constexpr std::uint32_t required_size = 0x408;
		if (buffer_length < required_size)
		{
			if (return_length_address)
			{
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &required_size, sizeof(required_size)));
			}
			write_nt_status(emulator, status_info_length_mismatch);
			return;
		}

		std::array<std::uint8_t, required_size> buf{};
		// HighestNodeNumber = 0 (single NUMA node), Reserved = 0
		// ActiveProcessorsGroupAffinity[0].Mask at offset 8
		const std::uint64_t mask = 0xFFF;
		std::memcpy(buf.data() + 0x08, &mask, sizeof(mask));

		static_cast<void>(emulator->write_virtual_memory(buffer_address, buf.data(), required_size));
		if (return_length_address)
		{
			static_cast<void>(emulator->write_virtual_memory(return_length_address, &required_size, sizeof(required_size)));
		}
		THREAD_LOG("NtQuerySystemInformation: class 0x37 (NUMA) -> hardcoded (size=0x{:X})", required_size);
		write_nt_status(emulator, status_success);
		return;
	}

	// intercept remaining classes that may leak host state
	if (info_class == 0x5B)
	{
		THREAD_LOG("NtQuerySystemInformation(0x{:X}): returning STATUS_ACCESS_DENIED", info_class);
		constexpr std::uint32_t status_access_denied = 0xC0000022;
		write_nt_status(emulator, status_access_denied);
		return;
	}

	if (info_class == 0xC5)
	{
		THREAD_LOG("NtQuerySystemInformation(0x{:X}): returning STATUS_NOT_SUPPORTED", info_class);
		constexpr std::uint32_t status_not_supported = 0xC00000BB;
		write_nt_status(emulator, status_not_supported);
		return;
	}

	if (info_class == 0xCA)
	{
		// undocumented class, 1 byte output - return a zero byte
		THREAD_LOG("NtQuerySystemInformation(0xCA): returning 1 byte zero");
		if (buffer_address && buffer_length >= 1)
		{
			const std::uint8_t zero = 0;
			static_cast<void>(emulator->write_virtual_memory(buffer_address, &zero, sizeof(zero)));
		}
		if (return_length_address)
		{
			constexpr std::uint32_t ret_len = 1;
			static_cast<void>(emulator->write_virtual_memory(return_length_address, &ret_len, sizeof(ret_len)));
		}
		write_nt_status(emulator, status_success);
		return;
	}

	if (info_class == 0xC0)
	{
		THREAD_LOG("NtQuerySystemInformation(0xC0): returning STATUS_NOT_IMPLEMENTED");
		write_nt_status(emulator, status_not_implemented);
		return;
	}

	if (info_class == 0xA5)
	{
		// undocumented class, 0x10 bytes output - return zeroed data
		constexpr std::uint32_t required = 0x10;
		THREAD_LOG("NtQuerySystemInformation(0xA5): returning 0x10 bytes zeroed");
		if (return_length_address)
		{
			static_cast<void>(emulator->write_virtual_memory(return_length_address, &required, sizeof(required)));
		}
		if (buffer_length < required)
		{
			write_nt_status(emulator, status_info_length_mismatch);
			return;
		}
		if (buffer_address)
		{
			std::array<std::uint8_t, 0x10> zeroed{};
			static_cast<void>(emulator->write_virtual_memory(buffer_address, zeroed.data(), zeroed.size()));
		}
		write_nt_status(emulator, status_success);
		return;
	}

	// fallback: forward to host for classes we haven't implemented
	const auto host_fn = get_host_nt_query_system_information();

	std::uint32_t status = status_not_implemented;

	if (!host_fn)
	{
		THREAD_WARN_LOG("NtQuerySystemInformation: class 0x{:X}, host fallback unavailable", info_class);
	}
	else
	{
		THREAD_LOG("NtQuerySystemInformation: forwarding class 0x{:X} to host", info_class);

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

		THREAD_LOG("NtQuerySystemInformation: host returned 0x{:X} (return_length=0x{:X})",
			status, host_return_length);

		if (info_class == system_module_information_ex && status == 0)
		{
			fixup_module_information_ex(emulator, host_buffer, host_return_length,
				buffer_address, buffer_length, "NtQuerySystemInformation");
		}

		if (info_class == system_module_information && status == 0)
		{
			fixup_module_information(emulator, host_buffer, host_return_length,
				buffer_address, buffer_length);
		}
	}

	if (status == status_info_length_mismatch && return_length_address)
	{
		std::uint32_t returned_length = 0;

		emulator_err_t error = emulator->read_virtual_memory(return_length_address, &returned_length, sizeof(returned_length));

		error.throw_if("read return length for logging");

		THREAD_LOG("NtQuerySystemInformation returning 0x{:X} (required_size=0x{:X})", status, returned_length);
	}
	else
	{
		THREAD_LOG("NtQuerySystemInformation returning 0x{:X}", status);
	}

	write_nt_status(emulator, status);
}

static void handle_query_system_information_ex(const std::shared_ptr<emulator_t>& emulator,
	std::uint32_t info_class, emulator_t::address_type input_buffer_address,
	std::uint32_t input_buffer_length, emulator_t::address_type buffer_address,
	std::uint32_t buffer_length, emulator_t::address_type return_length_address)
{
	THREAD_LOG("NtQuerySystemInformationEx called (class=0x{:X}, input=0x{:X}, input_len=0x{:X}, "
		"buffer=0x{:X}, length=0x{:X}, return_length=0x{:X})",
		info_class, input_buffer_address, input_buffer_length,
		buffer_address, buffer_length, return_length_address);

	// SystemLogicalProcessorAndGroupInformation (0x6B) - return emulated data like sogen
	if (info_class == 0x6B)
	{
		std::uint16_t relationship = 0;
		if (input_buffer_length >= sizeof(relationship) && input_buffer_address)
		{
			static_cast<void>(emulator->read_virtual_memory(input_buffer_address, &relationship, sizeof(relationship)));
		}

		THREAD_LOG("NtQuerySystemInformationEx: class 0x6B (LogicalProcessorAndGroupInfo), relationship=0x{:X}", relationship);

		if (relationship == 4) // RelationGroup
		{
			constexpr std::uint32_t required_size = 0x50;
			if (buffer_length < required_size)
			{
				if (return_length_address)
				{
					static_cast<void>(emulator->write_virtual_memory(return_length_address, &required_size, sizeof(required_size)));
				}
				write_nt_status(emulator, status_info_length_mismatch);
				return;
			}

			std::array<std::uint8_t, required_size> buf{};
			// GROUP_RELATIONSHIP: MaximumGroupCount(2) + ActiveGroupCount(2) + Reserved(20) + GROUP_AFFINITY[]
			*reinterpret_cast<std::uint16_t*>(buf.data() + 0x00) = 1; // MaximumGroupCount
			*reinterpret_cast<std::uint16_t*>(buf.data() + 0x02) = 1; // ActiveGroupCount
			// GroupInfo[0]: MaximumProcessorCount, ActiveProcessorCount, Reserved, ActiveProcessorMask
			buf[0x18] = static_cast<std::uint8_t>(kernel::processor_count);
			buf[0x19] = static_cast<std::uint8_t>(kernel::processor_count);
			*reinterpret_cast<std::uint64_t*>(buf.data() + 0x20) = (1ULL << kernel::processor_count) - 1;

			static_cast<void>(emulator->write_virtual_memory(buffer_address, buf.data(), required_size));
			if (return_length_address)
			{
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &required_size, sizeof(required_size)));
			}
			write_nt_status(emulator, status_success);
			return;
		}

		if (relationship == 1 || relationship == 5) // RelationNumaNode or RelationNumaNodeEx
		{
			// header: Relationship (DWORD) + Size (DWORD) = 8 bytes, then NUMA_NODE_RELATIONSHIP body
			// body: NodeNumber (DWORD=4) + Reserved (18) + GroupCount (WORD=2) + GROUP_AFFINITY (UINT64+WORD+WORD[3]=16) = 40
			constexpr std::uint32_t root_size = 8;
			constexpr std::uint32_t body_size = 40;
			constexpr std::uint32_t required_size = root_size + body_size;

			if (return_length_address)
			{
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &required_size, sizeof(required_size)));
			}

			if (buffer_length < required_size)
			{
				write_nt_status(emulator, status_info_length_mismatch);
				return;
			}

			// write header: Relationship=RelationNumaNode, Size=required_size
			struct
			{
				std::uint32_t relationship;
				std::uint32_t size;
			} header{};
			header.relationship = 1; // RelationNumaNode
			header.size = required_size;
			static_cast<void>(emulator->write_virtual_memory(buffer_address, &header, root_size));

			// write zeroed NUMA_NODE_RELATIONSHIP body
			std::array<std::uint8_t, body_size> numa_body{};
			static_cast<void>(emulator->write_virtual_memory(buffer_address + root_size, numa_body.data(), body_size));

			THREAD_LOG("NtQuerySystemInformationEx: class 0x6B RelationNumaNode -> SUCCESS (size=0x{:X})", required_size);
			write_nt_status(emulator, status_success);
			return;
		}

		if (relationship == 0) // RelationProcessorCore
		{
			constexpr std::uint32_t root_size = 8;
			constexpr std::uint32_t body_size = 38; // Flags(1) + EfficiencyClass(1) + Reserved(20) + GroupCount(2) + GROUP_AFFINITY(16) - wait let me match sogen
			// EMU_PROCESSOR_RELATIONSHIP64: Flags(1) + EfficiencyClass(1) + Reserved(20) + GroupCount(WORD=2) + GroupMask[1](GROUP_AFFINITY=16) = 40
			constexpr std::uint32_t proc_body_size = 40;
			constexpr std::uint32_t required_size = root_size + proc_body_size;

			if (return_length_address)
			{
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &required_size, sizeof(required_size)));
			}

			if (buffer_length < required_size)
			{
				write_nt_status(emulator, status_info_length_mismatch);
				return;
			}

			struct
			{
				std::uint32_t relationship;
				std::uint32_t size;
			} header{};
			header.relationship = 0;
			header.size = required_size;
			static_cast<void>(emulator->write_virtual_memory(buffer_address, &header, root_size));

			std::array<std::uint8_t, proc_body_size> proc_body{};
			// GroupCount = 1
			*reinterpret_cast<std::uint16_t*>(proc_body.data() + 22) = 1;
			// GroupMask[0].Mask = 0x1 (one processor)
			*reinterpret_cast<std::uint64_t*>(proc_body.data() + 24) = 0x1;
			static_cast<void>(emulator->write_virtual_memory(buffer_address + root_size, proc_body.data(), proc_body_size));

			THREAD_LOG("NtQuerySystemInformationEx: class 0x6B RelationProcessorCore -> SUCCESS");
			write_nt_status(emulator, status_success);
			return;
		}

		if (relationship == 2) // RelationCache
		{
			constexpr std::uint32_t required_size = 0;
			if (return_length_address)
			{
				static_cast<void>(emulator->write_virtual_memory(return_length_address, &required_size, sizeof(required_size)));
			}
			write_nt_status(emulator, status_info_length_mismatch);
			return;
		}

		THREAD_LOG("NtQuerySystemInformationEx: class 0x6B relationship 0x{:X} -> STATUS_NOT_SUPPORTED", relationship);
		constexpr std::uint32_t status_not_supported = 0xC00000BB;
		write_nt_status(emulator, status_not_supported);
		return;
	}

	// todo: implement needed classes and remove host passthrough
	const auto host_fn = get_host_nt_query_system_information_ex();

	std::uint32_t status = status_not_implemented;

	if (!host_fn)
	{
		THREAD_WARN_LOG("NtQuerySystemInformationEx: class 0x{:X}, host fallback unavailable", info_class);
	}
	else
	{
		THREAD_LOG("NtQuerySystemInformationEx: forwarding class 0x{:X} to host", info_class);

		std::vector<std::uint8_t> input_buffer(input_buffer_length);

		if (input_buffer_length && input_buffer_address)
		{
			emulator_err_t error = emulator->read_virtual_memory(
				input_buffer_address, input_buffer.data(), input_buffer_length);

			error.throw_if("read host query input buffer from guest");
		}

		std::vector<std::uint8_t> host_buffer(buffer_length);
		ULONG host_return_length = 0;

		status = static_cast<std::uint32_t>(host_fn(
			info_class,
			input_buffer_length ? input_buffer.data() : nullptr,
			input_buffer_length,
			host_buffer.data(),
			buffer_length,
			&host_return_length));

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

		THREAD_LOG("NtQuerySystemInformationEx: host returned 0x{:X} (return_length=0x{:X})",
			status, host_return_length);

		if (info_class == system_module_information_ex && status == 0)
		{
			fixup_module_information_ex(emulator, host_buffer, host_return_length,
				buffer_address, buffer_length, "NtQuerySystemInformationEx");
		}

		if (info_class == system_module_information && status == 0)
		{
			fixup_module_information(emulator, host_buffer, host_return_length,
				buffer_address, buffer_length);
		}
	}

	if (status == status_info_length_mismatch && return_length_address)
	{
		std::uint32_t returned_length = 0;

		emulator_err_t error = emulator->read_virtual_memory(return_length_address, &returned_length, sizeof(returned_length));

		error.throw_if("read return length for logging");

		THREAD_LOG("NtQuerySystemInformationEx returning 0x{:X} (required_size=0x{:X})", status, returned_length);
	}
	else
	{
		THREAD_LOG("NtQuerySystemInformationEx returning 0x{:X}", status);
	}

	write_nt_status(emulator, status);
}

void redirect_ntoskrnl_sysinfo_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_query_system_information>(emulator, mapped_image, "NtQuerySystemInformation");
	redirect_handler<handle_query_system_information>(emulator, mapped_image, "ZwQuerySystemInformation");
	redirect_handler<handle_query_system_information_ex>(emulator, mapped_image, "NtQuerySystemInformationEx");
	redirect_handler<handle_query_system_information_ex>(emulator, mapped_image, "ZwQuerySystemInformationEx");
}