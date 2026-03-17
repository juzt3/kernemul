#include "image_loader.hpp"
#include "../emulator/object.hpp"
#include "../image/pdb/pdb_file.hpp"
#include "../impl/ntoskrnl/nt_debugger.hpp"
#include "../impl/ntoskrnl/nt_helpers.hpp"
#include "../filesystem/filesystem.hpp"
#include "kernel.hpp"
#include "kernel_string.hpp"

#include <portable_executable/image.hpp>
#include <portable_executable/file.hpp>

#include <spdlog/spdlog.h>
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

static PLIST_ENTRY get_module_list_entry_address(const emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& object)
{
	return reinterpret_cast<PLIST_ENTRY>(object.address()) + offsetof(_KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
}

static void set_module_list_entry_flink(emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& object, const PLIST_ENTRY flink)
{
	auto current = object.read();

	current.InLoadOrderLinks.Flink = flink;

	object.write(current);
}

static void set_module_list_entry_blink(emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& object, const PLIST_ENTRY blink)
{
	auto current = object.read();

	current.InLoadOrderLinks.Blink = blink;

	object.write(current);
}

static void set_module_list_entry_flink(emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& object, const emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& flink)
{
	const auto list_entry = get_module_list_entry_address(flink);

	set_module_list_entry_flink(object, list_entry);
}

static void set_module_list_entry_blink(emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& object, const emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& blink)
{
	const auto list_entry = get_module_list_entry_address(blink);

	set_module_list_entry_blink(object, list_entry);
}

static void set_list_entry_flink(emulator_object_t<LIST_ENTRY>& object, const PLIST_ENTRY flink)
{
	auto current = object.read();

	current.Flink = flink;

	object.write(current);
}

static void set_list_entry_blink(emulator_object_t<LIST_ENTRY>& object, const PLIST_ENTRY blink)
{
	auto current = object.read();

	current.Blink = blink;

	object.write(current);
}

static void set_loaded_module_list_flink(const emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& flink)
{
	const auto list_entry = get_module_list_entry_address(flink);

	set_list_entry_flink(kernel::ps_loaded_module_list, list_entry);
}

static void set_loaded_module_list_blink(const emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& blink)
{
	const auto list_entry = get_module_list_entry_address(blink);

	set_list_entry_blink(kernel::ps_loaded_module_list, list_entry);
}

static void collect_module_symbols(portable_executable::image_t* const pe_image, mapped_image_t& mapped_image)
{
	const auto local_image_address = pe_image->as<const std::uint8_t*>();

	for (const auto current_export : pe_image->exports())
	{
		const std::uint32_t rva = static_cast<std::uint32_t>(current_export.address - local_image_address);
		const emulator_t::address_type runtime_address = mapped_image.base_address() + rva;

		mapped_image.register_symbol(current_export.name, runtime_address);
	}

	try
	{
		auto pdb = pdb::load_pdb_for_image_buffer(pe_image->as<const void*>());

		for (const auto& symbol : pdb.symbols())
		{
			if (symbol.rva != 0)
			{
				const emulator_t::address_type runtime_address = mapped_image.base_address() + symbol.rva;

				mapped_image.register_symbol(symbol.name, runtime_address);
			}
		}

		spdlog::info("loaded {} pdb symbols for '{}'", pdb.symbol_count(), mapped_image.name());
	}
	catch (const std::exception& e)
	{
		spdlog::warn("failed to load pdb for '{}': {}", mapped_image.name(), e.what());
	}
}

static void add_to_loaded_module_list(const std::shared_ptr<emulator_t>& emulator, const std::shared_ptr<mapped_image_t>& mapped_image,
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

	const auto module_list = reinterpret_cast<PLIST_ENTRY>(kernel::ps_loaded_module_list.address());

	const std::shared_ptr<mapped_image_t>& last_entry = kernel::module_entries.empty()
		? nullptr
		: kernel::module_entries.back();

	contents.InLoadOrderLinks.Flink = module_list;
	contents.InLoadOrderLinks.Blink = last_entry
		? get_module_list_entry_address(last_entry->table_entry())
		: module_list;

	auto object = emulator_object_t<_KLDR_DATA_TABLE_ENTRY>::allocate(emulator, contents, mapped_image->name());

	if (last_entry)
	{
		set_module_list_entry_flink(last_entry->table_entry(), object);
	}
	else
	{
		set_loaded_module_list_flink(object);
	}

	set_loaded_module_list_blink(object);

	mapped_image->table_entry() = std::move(object);

	kernel::module_entries.push_back(mapped_image);
}

std::shared_ptr<mapped_image_t> kernel::map_kernel_image(const std::shared_ptr<emulator_t>& emulator,
	const std::string_view name, const bool fix_imports,
	const std::wstring_view directory)
{
	portable_executable::file_t pe_file(name);

	if (!pe_file.load())
	{
		spdlog::error("unable to load portable executable file");

		return { };
	}

	const auto pe_image = pe_file.image();
	const auto nt_headers = pe_image->nt_headers();

	const auto image_size = nt_headers->optional_header.size_of_image;

	const auto base_address = emulator->heap_allocate(image_size, prot_all, true);

	if (!base_address)
	{
		spdlog::error("unable to map kernel memory");

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
		spdlog::error("unable to write kernel memory");

		return { };
	}

	const mapped_image_t::address_type entry_point = *base_address + nt_headers->optional_header.address_of_entry_point;

	auto mapped_image = std::make_shared<mapped_image_t>(std::string(name), *base_address, entry_point, image_buffer);

	add_to_loaded_module_list(emulator, mapped_image, directory);
	collect_module_symbols(pe_image, *mapped_image);

	if (name == "ntoskrnl.exe")
	{
		initialize_ntoskrnl_debugger_state(emulator, *mapped_image);

		redirect_ntoskrnl_string_functions(emulator, *mapped_image);
		redirect_ntoskrnl_memory_functions(emulator, *mapped_image);
		redirect_ntoskrnl_time_functions(emulator, *mapped_image);
		redirect_ntoskrnl_registry_functions(emulator, *mapped_image);
		redirect_ntoskrnl_format_functions(emulator, *mapped_image);
		redirect_ntoskrnl_misc_functions(emulator, *mapped_image);
		redirect_ntoskrnl_file_functions(emulator, *mapped_image, kernel::filesystem);
		redirect_ntoskrnl_sysinfo_functions(emulator, *mapped_image);
	}

	return mapped_image;
}
