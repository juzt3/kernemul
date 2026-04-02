#include "image_loader.hpp"
#include "../emulator/object.hpp"
#include "../image/pdb/pdb_file.hpp"
#include "../impl/cng/cng_helpers.hpp"
#include "../impl/ntoskrnl/nt_crashdump.hpp"
#include "../impl/ntoskrnl/nt_debugger.hpp"
#include "../impl/ntoskrnl/nt_helpers.hpp"
#include "../impl/ntoskrnl/nt_object.hpp"
#include "../filesystem/filesystem.hpp"
#include "kernel.hpp"
#include "kernel_string.hpp"

#include <portable_executable/image.hpp>
#include <portable_executable/file.hpp>

#include "../util/logs.hpp"
#include <set>

static void relocate_image(portable_executable::image_t* const image, const emulator_t::address_type runtime_base_address)
{
	const auto nt_headers = image->nt_headers();
	const emulator_t::address_type delta = runtime_base_address - nt_headers->optional_header.image_base;

	for (const auto [descriptor, virtual_address] : image->relocations())
	{
		if (descriptor.type == portable_executable::relocation_type_t::dir64)
		{
			const auto patch = reinterpret_cast<std::uint64_t*>(image->as<std::uint64_t>() + virtual_address + descriptor.offset);

			*patch += delta;
		}
	}
}

static void fix_image_imports(portable_executable::image_t* const image)
{
	for (const auto current_import : image->imports())
	{
		const auto import_module = kernel::find_module(current_import.module_name);

		if (!import_module)
		{
			throw std::runtime_error("unable to find import module");
		}

		const auto module_symbol = import_module->find_symbol(current_import.import_name);

		if (!module_symbol)
		{
			throw std::runtime_error("unable to find symbol in module");
		}

		current_import.address = reinterpret_cast<std::uint8_t*>(*module_symbol);
	}
}

static emulator_t::address_type get_in_load_order_links_address(const kernel_image_t& image)
{
	return image.table_entry().address() + offsetof(_KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
}

static void write_list_entry_flink(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type list_address, const emulator_t::address_type flink)
{
	emulator_err_t error = emulator->write_virtual_memory(list_address, &flink, sizeof(flink));
	error.throw_if("write LIST_ENTRY.Flink");
}

static void write_list_entry_blink(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type list_address, const emulator_t::address_type blink)
{
	emulator_err_t error = emulator->write_virtual_memory(
		list_address + sizeof(emulator_t::address_type), &blink, sizeof(blink));
	error.throw_if("write LIST_ENTRY.Blink");
}

static void set_module_flink(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& image, const emulator_t::address_type flink)
{
	const auto links_address = get_in_load_order_links_address(image);

	emulator_err_t error = emulator->write_virtual_memory(links_address, &flink, sizeof(flink));
	error.throw_if("write module Flink");
}

static void set_module_blink(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& image, const emulator_t::address_type blink)
{
	const auto links_address = get_in_load_order_links_address(image) + sizeof(emulator_t::address_type);

	emulator_err_t error = emulator->write_virtual_memory(links_address, &blink, sizeof(blink));
	error.throw_if("write module Blink");
}

static void collect_module_symbols(portable_executable::image_t* const pe_image, kernel_image_t& mapped_image,
	const bool load_pdb)
{
	const auto local_image_address = pe_image->as<const std::uint8_t*>();

	for (const auto current_export : pe_image->exports())
	{
		const std::uint32_t rva = static_cast<std::uint32_t>(current_export.address - local_image_address);
		const emulator_t::address_type runtime_address = mapped_image.base_address() + rva;

		mapped_image.register_symbol(current_export.name, runtime_address);
	}

	if (!load_pdb)
	{
		return;
	}

	try
	{
		auto pdb = pdb::load_pdb_for_image_buffer(pe_image->as<const void*>(), mapped_image.name());

		for (const auto& symbol : pdb.symbols())
		{
			if (symbol.rva != 0)
			{
				const emulator_t::address_type runtime_address = mapped_image.base_address() + symbol.rva;

				mapped_image.register_symbol(symbol.name, runtime_address);
			}
		}

		GLOBAL_LOG("loaded {} pdb symbols for '{}'", pdb.symbol_count(), mapped_image.name());
	}
	catch (const std::exception& e)
	{
		GLOBAL_WARN_LOG("failed to load pdb for '{}': {}", mapped_image.name(), e.what());
	}
}

static void monitor_data_sections(const std::shared_ptr<emulator_t>& emulator,
                                  const std::shared_ptr<kernel_image_t>& mapped_image,
                                  const portable_executable::image_t* const pe_image)
{
	const auto nt_headers = pe_image->nt_headers();

	const auto headers_size = nt_headers->optional_header.size_of_headers;
	const auto& export_dir = nt_headers->optional_header.data_directories.export_directory;
	const auto export_start = export_dir.virtual_address;
	const auto export_end = export_start + export_dir.size;

	for (const auto& section : pe_image->sections())
	{
		if (section.characteristics.mem_execute)
		{
			continue;
		}

		if (section.virtual_address < headers_size)
		{
			continue;
		}

		const auto section_end_rva = section.virtual_address + section.virtual_size;

		if (export_start && section.virtual_address < export_end && section_end_rva > export_start)
		{
			continue;
		}

		const auto section_address = mapped_image->base_address() + section.virtual_address;
		const auto section_size = section.virtual_size;

		const emulator_err_t error = emulator->hook_memory(
			[emulator, mapped_image](const emulator_t::address_type accessed_address, const protection_t)
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				if (const auto symbol = mapped_image->find_symbol_by_address(accessed_address))
				{
					const auto offset = accessed_address - symbol->second;

					if (offset == 0)
					{
					THREAD_LOG("instruction at 0x{:X} accessed {}!{}", rip, mapped_image->name(), symbol->first);
				}
				else
				{
					THREAD_LOG("instruction at 0x{:X} accessed {}!{}+0x{:X}", rip, mapped_image->name(), symbol->first, offset);
				}
			}
			else
			{
				const auto offset = accessed_address - mapped_image->base_address();

				THREAD_LOG("instruction at 0x{:X} accessed {}+0x{:X} (0x{:X})", rip, mapped_image->name(), offset, accessed_address);
				}

				return false;
			},
			prot_read_write,
			section_address,
			section_address + section_size
		).error_or({});

		error.throw_if("data section hook");
	}
}

static void add_to_loaded_module_list(const std::shared_ptr<emulator_t>& emulator, const std::shared_ptr<kernel_image_t>& mapped_image,
	const std::wstring_view directory = L"C:\\Windows\\System32\\")
{
	_KLDR_DATA_TABLE_ENTRY contents = { };

	contents.DllBase = reinterpret_cast<void*>(mapped_image->base_address());
	contents.SizeOfImage = static_cast<std::uint32_t>(mapped_image->size());
	contents.EntryPoint = reinterpret_cast<void*>(mapped_image->entry_point());

	const auto& name = mapped_image->name();
	const std::wstring wide_name(name.begin(), name.end());
	const auto full_path = std::wstring(L"\\??\\").append(directory).append(wide_name);

	contents.BaseDllName = kernel::init_unicode_string(*emulator, wide_name);
	contents.FullDllName = kernel::init_unicode_string(*emulator, full_path);

	const auto list_head = kernel::ps_loaded_module_list.address();

	const auto& last_entry = kernel::module_entries.empty()
		? nullptr
		: kernel::module_entries.back();

	const auto last_links = last_entry
		? get_in_load_order_links_address(*last_entry)
		: list_head;

	contents.InLoadOrderLinks.Flink = reinterpret_cast<PLIST_ENTRY>(list_head);
	contents.InLoadOrderLinks.Blink = reinterpret_cast<PLIST_ENTRY>(last_links);

	auto object = emulator_object_t<_KLDR_DATA_TABLE_ENTRY>::allocate(emulator, contents, mapped_image->name());

	mapped_image->table_entry() = std::move(object);

	const auto self_links = get_in_load_order_links_address(*mapped_image);

	if (last_entry)
	{
		set_module_flink(emulator, *last_entry, self_links);
	}
	else
	{
		write_list_entry_flink(emulator, list_head, self_links);
	}

	write_list_entry_blink(emulator, list_head, self_links);

	kernel::module_entries.push_back(mapped_image);
}

std::shared_ptr<kernel_image_t> kernel::map_kernel_image(const std::shared_ptr<emulator_t>& emulator,
	const std::string_view name, const bool fix_imports,
	const std::wstring_view directory)
{
	portable_executable::file_t pe_file(name);

	if (!pe_file.load())
	{
		GLOBAL_ERR_LOG("unable to load portable executable file");

		return { };
	}

	const auto pe_image = pe_file.image();
	const auto nt_headers = pe_image->nt_headers();

	const auto image_size = nt_headers->optional_header.size_of_image;

	const auto base_address = emulator->heap_allocate(image_size, prot_all, true);

	if (!base_address)
	{
		GLOBAL_ERR_LOG("unable to map kernel memory");

		return { };
	}

	if (const auto load_config = pe_image->load_config())
	{
		if (const auto security_cookie_absolute = load_config->security_cookie)
		{
			const auto security_cookie_rva = security_cookie_absolute - nt_headers->optional_header.image_base;

			*reinterpret_cast<std::uint64_t*>(pe_image->as<std::uint64_t>() + security_cookie_rva) += *base_address;
		}
	}

	relocate_image(pe_image, *base_address);

	if (fix_imports)
	{
		fix_image_imports(pe_image);
	}

	const auto image_start = pe_image->as<const std::uint8_t*>();
	const std::vector image_buffer(image_start, image_start + nt_headers->optional_header.size_of_image);

	if (const auto error = emulator->write_virtual_memory(*base_address, image_buffer))
	{
		GLOBAL_ERR_LOG("unable to write kernel memory");

		return { };
	}

	const kernel_image_t::address_type entry_point = *base_address + nt_headers->optional_header.address_of_entry_point;

	auto mapped_image = std::make_shared<kernel_image_t>(std::string(name), *base_address, entry_point, image_buffer);

	GLOBAL_LOG("loaded '{}' at 0x{:X} (size=0x{:X})", name, *base_address, image_buffer.size());

	const bool is_main_emulated_image = fix_imports;

	collect_module_symbols(pe_image, *mapped_image, !is_main_emulated_image);

	const bool is_ntoskrnl = name == "ntoskrnl.exe";

	if (is_ntoskrnl)
	{
		if (const auto symbol = mapped_image->find_symbol("PsLoadedModuleList"))
		{
			ps_loaded_module_list = emulator_object_t<_LIST_ENTRY>::view_at(emulator, *symbol, "PsLoadedModuleList");
		}
	}

	add_to_loaded_module_list(emulator, mapped_image, directory);

	if (!is_main_emulated_image)
	{
		monitor_data_sections(emulator, mapped_image, pe_image);
	}

	if (name == "cng.sys")
	{
		redirect_cng_bcrypt_functions(emulator, *mapped_image);
	}

	if (is_ntoskrnl)
	{
		initialize_ntoskrnl_debugger_state(emulator, *mapped_image);
		initialize_ntoskrnl_object_types(emulator, *mapped_image);

		redirect_ntoskrnl_string_functions(emulator, *mapped_image);
		redirect_ntoskrnl_memory_functions(emulator, *mapped_image);
		redirect_ntoskrnl_time_functions(emulator, *mapped_image);
		redirect_ntoskrnl_registry_functions(emulator, *mapped_image);
		redirect_ntoskrnl_format_functions(emulator, *mapped_image);
		redirect_ntoskrnl_misc_functions(emulator, *mapped_image);
		redirect_ntoskrnl_file_functions(emulator, *mapped_image);
		redirect_ntoskrnl_sysinfo_functions(emulator, *mapped_image);
		redirect_ntoskrnl_object_functions(emulator, *mapped_image);
		redirect_ntoskrnl_debugger_functions(emulator, *mapped_image);
		redirect_ntoskrnl_crashdump_functions(emulator, *mapped_image);
	}

	return mapped_image;
}
