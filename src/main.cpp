#include "emulator/backend/hypermulator_backend.hpp"
#include "emulator/backend/unicorn_backend.hpp"
#include "emulator/emulator.hpp"

#include <portable_executable/image.hpp>
#include <portable_executable/file.hpp>
#include <spdlog/spdlog.h>

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

static std::optional<mapped_image_t> map_kernel_image(emulator_t& emulator, const std::string_view name)
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

	const auto base_address = emulator.heap_allocate(image_size, prot_all);

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

	if (const auto error = emulator.write_virtual_memory(*base_address, image_buffer))
	{
		spdlog::error("unable to write kernel memory");

		return { };
	}

	return mapped_image_t{
		.base_address = *base_address, .size = image_size,
		.entry_point = *base_address + nt_headers->optional_header.address_of_entry_point
	};
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

	try
	{
		const auto emulator = std::static_pointer_cast<emulator_t>(std::make_shared<hypermulator_t>());

		set_up_stack(*emulator);

		const auto pe_image = map_kernel_image(*emulator, pe_file_name);

	    const emulator_t::address_type base_address = pe_image->base_address;
	    const emulator_t::address_type end_address = base_address + pe_image->size;
		const emulator_t::address_type entry_point_address = pe_image->entry_point;

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
