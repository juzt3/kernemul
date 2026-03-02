#include "emulator/backend/hypermulator_backend.hpp"
#include "emulator/backend/unicorn_backend.hpp"
#include "emulator/object.hpp"

#include <portable_executable/image.hpp>
#include <portable_executable/file.hpp>
#include <spdlog/spdlog.h>

#include "kernel_def.hpp"

namespace kernel
{
	static emulator_object_t<_KUSER_SHARED_DATA> user_shared_data;

	static emulator_object_t<_LIST_ENTRY> ps_loaded_module_list;
	static std::vector<emulator_object_t<_NT_LDR_DATA_TABLE_ENTRY>> module_entries;
}

struct mapped_image_t
{
	emulator_t::address_type base_address;
	emulator_t::size_type size;

	emulator_t::address_type entry_point;
};

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

static PLIST_ENTRY get_module_list_entry_address(const emulator_object_t<_NT_LDR_DATA_TABLE_ENTRY>& object)
{
	return reinterpret_cast<PLIST_ENTRY>(object.address()) + offsetof(_NT_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
}

static void set_module_list_entry_flink(emulator_object_t<_NT_LDR_DATA_TABLE_ENTRY>& object, const PLIST_ENTRY flink)
{
	auto current = object.read();

	current.InLoadOrderLinks.Flink = flink;

	object.write(current);
}

static void set_module_list_entry_blink(emulator_object_t<_NT_LDR_DATA_TABLE_ENTRY>& object, const PLIST_ENTRY blink)
{
	auto current = object.read();

	current.InLoadOrderLinks.Blink = blink;

	object.write(current);
}

static void set_module_list_entry_flink(emulator_object_t<_NT_LDR_DATA_TABLE_ENTRY>& object, const emulator_object_t<_NT_LDR_DATA_TABLE_ENTRY>& flink)
{
	const auto list_entry = get_module_list_entry_address(flink);

	set_module_list_entry_flink(object, list_entry);
}

static void set_module_list_entry_blink(emulator_object_t<_NT_LDR_DATA_TABLE_ENTRY>& object, const emulator_object_t<_NT_LDR_DATA_TABLE_ENTRY>& blink)
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

static void set_loaded_module_list_flink(const emulator_object_t<_NT_LDR_DATA_TABLE_ENTRY>& flink)
{
	const auto list_entry = get_module_list_entry_address(flink);

	set_list_entry_flink(kernel::ps_loaded_module_list, list_entry);
}

static void set_loaded_module_list_blink(const emulator_object_t<_NT_LDR_DATA_TABLE_ENTRY>& blink)
{
	const auto list_entry = get_module_list_entry_address(blink);

	set_list_entry_blink(kernel::ps_loaded_module_list, list_entry);
}

static void add_to_loaded_module_list(const std::shared_ptr<emulator_t>& emulator, const mapped_image_t& image)
{
	_NT_LDR_DATA_TABLE_ENTRY contents = { };

	contents.DllBase = reinterpret_cast<void*>(image.base_address);
	contents.SizeOfImage = static_cast<std::uint32_t>(image.size);
	contents.EntryPoint = reinterpret_cast<void*>(image.entry_point);

	const auto module_list = reinterpret_cast<PLIST_ENTRY>(kernel::ps_loaded_module_list.address());

	contents.InLoadOrderLinks.Flink = module_list;
	contents.InLoadOrderLinks.Blink = kernel::module_entries.empty()
		                                  ? module_list
		                                  : get_module_list_entry_address(kernel::module_entries.back());

	auto object = emulator_object_t<_NT_LDR_DATA_TABLE_ENTRY>::allocate(emulator, contents);

	if (kernel::module_entries.empty())
	{
		set_loaded_module_list_flink(object);
	}
	else
	{
		set_module_list_entry_flink(kernel::module_entries.back(), object);
	}

	set_loaded_module_list_blink(object);

	kernel::module_entries.push_back(std::move(object));
}

static std::optional<mapped_image_t> map_kernel_image(const std::shared_ptr<emulator_t>& emulator, const std::string_view name)
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

	const auto load_config = pe_image->load_config();

	if (const auto security_cookie_absolute = load_config->security_cookie)
	{
		const auto security_cookie_rva = security_cookie_absolute - nt_headers->optional_header.image_base;

		*reinterpret_cast<std::uint64_t*>(pe_image->as<std::uint64_t>() + security_cookie_rva) += *base_address;
	}

	relocate_image(pe_image, *base_address);

	const auto image_start = pe_image->as<const std::uint8_t*>();
	const std::span image_buffer(image_start, image_start + nt_headers->optional_header.size_of_image);

	if (const auto error = emulator->write_virtual_memory(*base_address, image_buffer))
	{
		spdlog::error("unable to write kernel memory");

		return { };
	}

	const auto image = mapped_image_t{
		.base_address = *base_address, .size = image_size,
		.entry_point = *base_address + nt_headers->optional_header.address_of_entry_point
	};

	add_to_loaded_module_list(emulator, image);

	return image;
}

static void set_up_user_shared_data(const std::shared_ptr<emulator_t>& emulator)
{
	_KUSER_SHARED_DATA contents = { };

	contents.NtBuildNumber = 19045;
	contents.NtMajorVersion = 10;
	contents.NtMinorVersion = 0;

	kernel::user_shared_data = emulator_object_t<_KUSER_SHARED_DATA>::allocate_at(emulator, contents, 0xFFFFF78000000000);
}

static void set_up_ps_loaded_module_list(const std::shared_ptr<emulator_t>& emulator)
{
	kernel::ps_loaded_module_list = emulator_object_t<_LIST_ENTRY>::allocate(emulator);
}

static void set_up_stack(emulator_t& emulator)
{
	constexpr emulator_t::size_type stack_size = 0x10000;

	const auto stack_base_address = emulator.heap_allocate(stack_size, prot_read_write);

	emulator_err_t error = stack_base_address.error_or({});

	error.throw_if("unable to map stack");

	const emulator_t::address_type starting_rsp_value = *stack_base_address + stack_size - 0x1000;

	emulator.write_register<x86::reg::rsp>(starting_rsp_value);

	error = emulator.write_virtual_memory(starting_rsp_value, &emulator_t::thread_return_address, sizeof(emulator_t::thread_return_address));

	error.throw_if("unable to set return address");
}

std::int32_t main()
{
	constexpr std::string_view pe_file_name = "test.bin";
	constexpr std::string_view nt_file_name = "ntoskrnl.exe";

	try
	{
		const auto emulator = std::static_pointer_cast<emulator_t>(std::make_shared<hypermulator_t>());

		set_up_stack(*emulator);
		set_up_ps_loaded_module_list(emulator);
		set_up_user_shared_data(emulator);

		const auto nt_image = map_kernel_image(emulator, nt_file_name);
		const auto pe_image = map_kernel_image(emulator, pe_file_name);

	    const emulator_t::address_type base_address = pe_image->base_address;
	    const emulator_t::address_type end_address = base_address + pe_image->size;
		const emulator_t::address_type entry_point_address = pe_image->entry_point;

		spdlog::info("mapped ntoskrnl at 0x{:X}", nt_image->base_address);
		spdlog::info("mapped image at 0x{:X}", base_address);

		emulator_err_t error = emulator->hook_basic_block(
			[emulator]()
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				spdlog::info("basic block executed at 0x{:X}", rip);
			},
			base_address,
			end_address
		).error_or({});
		 
		error.throw_if("basic block hook attach");

		error = emulator->hook_invalid_memory(
			[emulator](const emulator_t::address_type faulting_address, const protection_t access) -> bool
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				spdlog::info("instruction at 0x{:X} accessed invalid memory address 0x{:X} with access type of {}", rip, faulting_address, static_cast<std::uint32_t>(access));

				return false;
			},
			prot_all,
			emulator_t::default_start_address,
			emulator_t::default_end_address
		).error_or({});

		error.throw_if("invalid memory hook attach");

		error = emulator->run_at(entry_point_address, emulator_t::thread_return_address);

		const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
		const auto rax = emulator->read_register<x86::reg::rax, emulator_t::address_type>();

		spdlog::info("emulation finished at rip=0x{:X}, rax=0x{:X}", rip, rax);

		error.throw_if("emulation running");
	}
	catch (const std::exception& e)
	{
		spdlog::error(e.what());
	}

	return 0;
}
