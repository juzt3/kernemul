#include "emulator/backend/hypermulator_backend.hpp"
#include "emulator/backend/unicorn_backend.hpp"
#include "emulator/emulator.hpp"

#include <portable_executable/image.hpp>
#include <portable_executable/file.hpp>
#include <spdlog/spdlog.h>

static void set_up_stack(emulator_t& emulator)
{
	constexpr emulator_t::address_type stack_base_address = 0x10000;
	constexpr emulator_t::size_type stack_size = 0x10000;

	constexpr emulator_t::address_type starting_rsp_value = stack_base_address + stack_size - 0x1000;

	emulator_err_t error = emulator.map_memory(stack_base_address, stack_size, prot_read_write);

	error.throw_if("unable to map stack");

	emulator.write_register<x86::reg::rsp>(starting_rsp_value);

	error = emulator.write_memory(starting_rsp_value, &emulator_t::thread_return_address, sizeof(emulator_t::thread_return_address));

	error.throw_if("unable to set return address");
}

std::int32_t main()
{
	constexpr std::string_view pe_file_name = "test.bin";

	portable_executable::file_t pe_file(pe_file_name);

	if (!pe_file.load())
	{
		spdlog::error("unable to load portable executable file");

		return 1;
	}

	const auto pe_image = pe_file.image();
	const auto nt_headers = pe_image->nt_headers();

	try
	{
		const auto emulator = std::static_pointer_cast<emulator_t>(std::make_shared<unicorn_emulator_t>());

		set_up_stack(*emulator);

		const emulator_t::address_type code_address = nt_headers->optional_header.image_base;
		const emulator_t::address_type code_end_address = code_address + nt_headers->optional_header.size_of_image;
		const emulator_t::address_type entry_point_address = code_address + nt_headers->optional_header.address_of_entry_point;

		const auto image_start = pe_image->as<const std::uint8_t*>();
		const std::span image_buffer(image_start, image_start + nt_headers->optional_header.size_of_image);

		emulator_err_t error = emulator->load_memory(code_address, image_buffer, prot_all);

		error.throw_if("memory loading");

		error = emulator->hook_basic_block(
			[emulator]()
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				spdlog::info("basic block executed at 0x{:X}", rip);
			},
			code_address,
			code_end_address
		).error_or({});

		error.throw_if("basic block hook attach");

		error = emulator->hook_invalid_memory(
			[emulator](const emulator_t::address_type faulting_address, const protection_t access) -> bool
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

				spdlog::info("instruction at 0x{:X} access invalid memory address 0x{:X} with access type of {}", rip, faulting_address, static_cast<std::uint32_t>(access));

				return false;
			},
			prot_all,
			emulator_t::default_start_address,
			emulator_t::default_end_address
		).error_or({});

		error.throw_if("invalid memory hook attach");

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
