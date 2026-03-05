#include "emulator/backend/hypermulator_backend.hpp"
#include "emulator/backend/unicorn_backend.hpp"
#include "emulator/object.hpp"

#include <portable_executable/image.hpp>
#include <portable_executable/file.hpp>
#include <ia32-doc/ia32.hpp>
#include <spdlog/spdlog.h>

#include "kernel_def.hpp"

struct mapped_image_t
{
	using string_type = std::string;
	using address_type = emulator_t::address_type;
	using size_type = emulator_t::size_type;

	mapped_image_t(string_type _name, const address_type _base_address, const size_type _size, const address_type _entry_point)
			:	name(std::move(_name)),
				base_address(_base_address),
				size(_size),
				entry_point(_entry_point) { }

	string_type name;

	address_type base_address;
	size_type size;

	address_type entry_point;

	emulator_object_t<_KLDR_DATA_TABLE_ENTRY> table_entry;
};

namespace kernel
{
	static emulator_object_t<_KUSER_SHARED_DATA> user_shared_data;

	static emulator_object_t<_KPCR> kpcr;
	static emulator_object_t<_KPRCB> kprcb;

	static emulator_object_t<_LIST_ENTRY> ps_loaded_module_list;
	static std::vector<std::shared_ptr<mapped_image_t>> module_entries;

	static std::shared_ptr<mapped_image_t> emulated_module;

	using function_implementation_t = std::function<void()>;

	static std::unordered_map<emulator_t::address_type, function_implementation_t> redirected_functions;

	[[nodiscard]] std::shared_ptr<mapped_image_t> find_module(const std::string_view name)
	{
		const auto it = std::ranges::find(module_entries, name, &mapped_image_t::name);

		return it != std::ranges::end(module_entries) ? *it : nullptr;
	}

	[[nodiscard]] std::optional<function_implementation_t> find_redirected_function(const emulator_t::address_type address)
	{
		const auto it = redirected_functions.find(address);
		
		if (it != std::ranges::end(redirected_functions))
		{
			return it->second;
		}

		return std::nullopt;
	}
}

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

static void add_to_loaded_module_list(const std::shared_ptr<emulator_t>& emulator, const std::shared_ptr<mapped_image_t>& image)
{
	_KLDR_DATA_TABLE_ENTRY contents = { };

	contents.DllBase = reinterpret_cast<void*>(image->base_address);
	contents.SizeOfImage = static_cast<std::uint32_t>(image->size);
	contents.EntryPoint = reinterpret_cast<void*>(image->entry_point);

	const auto module_list = reinterpret_cast<PLIST_ENTRY>(kernel::ps_loaded_module_list.address());

	const std::shared_ptr<mapped_image_t>& last_entry = kernel::module_entries.empty()
		                                                    ? nullptr
		                                                    : kernel::module_entries.back();

	contents.InLoadOrderLinks.Flink = module_list;
	contents.InLoadOrderLinks.Blink = last_entry
		                                  ? get_module_list_entry_address(last_entry->table_entry)
		                                  : module_list;

	auto object = emulator_object_t<_KLDR_DATA_TABLE_ENTRY>::allocate(emulator, contents, image->name);

	if (last_entry)
	{
		set_module_list_entry_flink(last_entry->table_entry, object);
	}
	else
	{
		set_loaded_module_list_flink(object);
	}

	set_loaded_module_list_blink(object);

	image->table_entry = std::move(object);

	kernel::module_entries.push_back(image);
}

static void redirect_image_export(const kernel::function_implementation_t& function_impl,
                                  const portable_executable::image_t* const pe_image,
                                  const mapped_image_t& mapped_image, const std::string_view name)
{
	const auto local_export_address = pe_image->find_export(name);

	if (!local_export_address)
	{
		throw std::runtime_error("unable to find export");
	}

	const std::uint32_t rva = static_cast<std::uint32_t>(local_export_address - pe_image->as<const std::uint8_t*>());

	const emulator_t::address_type export_runtime_address = mapped_image.base_address + rva;

	kernel::redirected_functions[export_runtime_address] = function_impl;
}

static void write_nt_success(const std::shared_ptr<emulator_t>& emulator)
{
	emulator->write_register<x86::reg::rax>(0);
}

static void write_dummy_handle(const std::shared_ptr<emulator_t>& emulator, const emulator_t::address_type handle_address)
{
	constexpr std::uint64_t handle_value = 0x1337;

	const emulator_err_t error = emulator->write_virtual_memory(handle_address, &handle_value, sizeof(handle_value));

	error.throw_if("write memory");
}

static void redirect_ntoskrnl_functions(const std::shared_ptr<emulator_t>& emulator, const mapped_image_t& mapped_image,
                                        const portable_executable::image_t* const pe_image)
{
	redirect_image_export(
		[emulator]
		{
			const auto r9 = emulator->read_register<x86::reg::r9, std::uint64_t>();

			spdlog::info("RtlWriteRegistryValue called with type: 0x{:X}", r9);

			write_nt_success(emulator);
		},
		pe_image,
		mapped_image,
		"RtlWriteRegistryValue"
	);

	redirect_image_export(
		[emulator]
		{
			spdlog::info("RtlDeleteRegistryValue called");

			write_nt_success(emulator);
		},
		pe_image,
		mapped_image,
		"RtlDeleteRegistryValue"
	);

	redirect_image_export(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rdx = emulator->read_register<x86::reg::rdx, std::uint32_t>();

			spdlog::info("ZwOpenKey called (desired access=0x{:X})", rdx);

			write_dummy_handle(emulator, rcx);

			write_nt_success(emulator);
		},
		pe_image,
		mapped_image,
		"ZwOpenKey"
	);

	redirect_image_export(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();

			spdlog::info("ZwFlushKey called (key handle=0x{:X})", rcx);

			write_nt_success(emulator);
		},
		pe_image,
		mapped_image,
		"ZwFlushKey"
	);

	redirect_image_export(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();

			spdlog::info("ZwClose called (handle=0x{:X})", rcx);

			write_nt_success(emulator);
		},
		pe_image,
		mapped_image,
		"ZwClose"
	);
}

static std::shared_ptr<mapped_image_t> map_kernel_image(const std::shared_ptr<emulator_t>& emulator,
                                                        const std::string_view name)
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

	auto image = std::make_shared<mapped_image_t>(std::string(name), *base_address, image_size, *base_address + nt_headers->optional_header.address_of_entry_point);

	add_to_loaded_module_list(emulator, image);

	if (name == "ntoskrnl.exe")
	{
		redirect_ntoskrnl_functions(emulator, *image, pe_image);
	}

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

static emulator_object_t<_DRIVER_OBJECT> set_up_driver_object(const std::shared_ptr<emulator_t>& emulator, const mapped_image_t& image)
{
	_DRIVER_OBJECT contents = { };

	contents.DriverSection = reinterpret_cast<void*>(image.table_entry.address());
	contents.DriverStart = reinterpret_cast<void*>(image.base_address);
	contents.DriverSize = static_cast<std::uint32_t>(image.size);

	return emulator_object_t<_DRIVER_OBJECT>::allocate(emulator, contents, image.name);
}

static void set_up_driver_entry(const std::shared_ptr<emulator_t>& emulator)
{
	const auto driver_object = set_up_driver_object(emulator, *kernel::emulated_module);

	emulator->write_register<x86::reg::rcx>(driver_object.address());
}

static void set_up_ps_loaded_module_list(const std::shared_ptr<emulator_t>& emulator)
{
	kernel::ps_loaded_module_list = emulator_object_t<_LIST_ENTRY>::allocate(emulator, "PsLoadedModuleList");
}

static void set_up_stack(emulator_t& emulator)
{
	constexpr emulator_t::size_type stack_size = 0x10000;

	const auto stack_base_address = emulator.heap_allocate(stack_size, prot_read_write);

	emulator_err_t error = stack_base_address.error_or({});

	error.throw_if("map stack");

	const emulator_t::address_type starting_rsp_value = *stack_base_address + stack_size - 0x1000 - 8;

	emulator.write_register<x86::reg::rsp>(starting_rsp_value);

	error = emulator.write_virtual_memory(starting_rsp_value, &emulator_t::thread_return_address, sizeof(emulator_t::thread_return_address));

	error.throw_if("set return address");
}

static void set_up_kprcb(const std::shared_ptr<emulator_t>& emulator)
{
	kernel::kprcb = emulator_object_t<_KPRCB>::allocate(emulator);
}

static void set_up_kpcr(const std::shared_ptr<emulator_t>& emulator)
{
	set_up_kprcb(emulator);

	kernel::kpcr = emulator_object_t<_KPCR>::allocate(emulator);

	_KPCR contents = { };

	contents.Self = reinterpret_cast<_KPCR*>(kernel::kpcr.address());
	contents.CurrentPrcb = reinterpret_cast<_KPRCB*>(kernel::kprcb.address());

	kernel::kpcr.write(contents);
}

static void set_up_kernel_gs(const std::shared_ptr<emulator_t>& emulator)
{
	set_up_kpcr(emulator);

	const emulator_err_t error = emulator->write_gs_base(kernel::kpcr.address());

	error.throw_if("write kernel gs base");

	spdlog::info("mapped kernel gs at 0x{:X}", kernel::kpcr.address());
}

static void set_up_idt(const std::shared_ptr<emulator_t>& emulator, const mapped_image_t& nt_image)
{
	constexpr std::uint32_t handler_count = 256;
	constexpr emulator_t::size_type idt_size = handler_count * sizeof(segment_descriptor_interrupt_gate_64);

	const auto idt_base_address = emulator->heap_allocate(idt_size, prot_read, true);

	emulator_err_t error = idt_base_address.error_or({});

	error.throw_if("map IDT");

	const emulator_t::address_type handler_address = nt_image.base_address + (nt_image.size / 2);

	for (std::uint32_t i = 0; i < handler_count; i++)
	{
		const std::uint32_t offset = i * sizeof(segment_descriptor_interrupt_gate_64);

		const std::string name = std::format("IDT vector #{:X}", i);

		auto entry_object = emulator_object_t<segment_descriptor_interrupt_gate_64>(emulator, *idt_base_address + offset, name);

		segment_descriptor_interrupt_gate_64 contents = { };

		contents.offset_low = handler_address & 0xFFFF;
		contents.offset_middle = (handler_address >> 16) & 0xFFFF;
		contents.offset_high = (handler_address >> 32) & 0xFFFF'FFFF;

		entry_object.write(contents);
	}

	error = emulator->write_idt(*idt_base_address, idt_size - 1);

	error.throw_if("loading IDT");

	spdlog::info("mapped IDT at 0x{:X}", *idt_base_address);
}

std::int32_t main()
{
	constexpr std::string_view pe_file_name = "test.bin";
	constexpr std::string_view nt_file_name = "ntoskrnl.exe";

	try
	{
		const auto emulator = std::static_pointer_cast<emulator_t>(std::make_shared<hypermulator_t>());

		set_up_stack(*emulator);
		set_up_kernel_gs(emulator);
		set_up_ps_loaded_module_list(emulator);
		set_up_user_shared_data(emulator);

		const auto nt_image = map_kernel_image(emulator, nt_file_name);

		kernel::emulated_module = map_kernel_image(emulator, pe_file_name);

		set_up_idt(emulator, *nt_image);

	    const emulator_t::address_type base_address = kernel::emulated_module->base_address;
		const emulator_t::address_type entry_point_address = kernel::emulated_module->entry_point;

		spdlog::info("mapped ntoskrnl at 0x{:X}", nt_image->base_address);
		spdlog::info("mapped image at 0x{:X}", base_address);

		emulator_err_t error = emulator->hook_basic_block(
			[emulator]()
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				if (const auto redirected_function = kernel::find_redirected_function(rip))
				{
					spdlog::info("redirecting function at 0x{:X}", rip);

					(*redirected_function)();

					const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

					emulator_t::address_type return_address = 0;

					const emulator_err_t read_error = emulator->read_virtual_memory(rsp, &return_address, sizeof(return_address));

					read_error.throw_if("read from stack");

					emulator->write_register<x86::reg::rsp>(rsp + 8);
					emulator->write_register<x86::reg::rip>(return_address);
				}
				else
				{
					spdlog::error("unimplemented function at 0x{:X}", rip);

					emulator->write_register<x86::reg::rip, emulator_t::address_type>(-1);
				}
			},
			nt_image->base_address,
			nt_image->base_address + nt_image->size
		).error_or({});
		 
		error.throw_if("basic block hook attach");

		error = emulator->hook_instruction(x86::insn::cpuid,
			[emulator]()
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
				const auto rax = emulator->read_register<x86::reg::rax, emulator_t::address_type>();

				spdlog::info("cpuid executed at 0x{:X} (rax=0x{:X})", rip, rax);

				return false;
			},
			emulator_t::default_start_address,
			emulator_t::default_end_address
		).error_or({});

		error.throw_if("instruction hook attach");

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

		set_up_driver_entry(emulator);

		error = emulator->run_at(entry_point_address, emulator_t::thread_return_address);

		const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
	
		spdlog::info("emulation finished at rip=0x{:X}", rip);

		error.throw_if("emulation running");
	}
	catch (const std::exception& e)
	{
		spdlog::error(e.what());
	}

	return 0;
}
