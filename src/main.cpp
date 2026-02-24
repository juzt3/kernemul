#include "emulator/backend/unicorn_backend.hpp"
#include "emulator/emulator.hpp"

#include <portable_executable/image.hpp>
#include <portable_executable/file.hpp>
#include <spdlog/spdlog.h>

static void fill_with_nops(emulator_t& emulator, const emulator_t::address_type address, const std::size_t count)
{
	const std::vector nop_page(count, static_cast<std::uint8_t>(0x90));

	const auto error = emulator.write_memory(address, nop_page);

	error.throw_if("nop");
}

static void set_up_stack(emulator_t& emulator)
{
	constexpr emulator_t::address_type stack_base_address = 0x10000;
	constexpr emulator_t::size_type stack_size = 0x10000;

	constexpr emulator_t::address_type starting_rsp_value = stack_base_address + stack_size - 0x1000;

	emulator_err_t error = emulator.map_memory(stack_base_address, stack_size, prot_read_write);

	error.throw_if("unable to map stack");

	error = emulator.write_register(x86::reg::rsp, &starting_rsp_value);

	error.throw_if("unable to set stack pointer");

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
		const auto emulator = std::make_shared<unicorn_emulator_t>();

		set_up_stack(*emulator);

		const emulator_t::address_type code_address = nt_headers->optional_header.image_base;
		const emulator_t::address_type code_end_address = code_address + nt_headers->optional_header.size_of_image;
		const emulator_t::address_type entry_point_address = code_address + nt_headers->optional_header.address_of_entry_point;

		const auto image_start = pe_image->as<const std::uint8_t*>();
		const std::span image_buffer(image_start, image_start + nt_headers->optional_header.size_of_image);

		const auto start_time = std::chrono::high_resolution_clock::now();

		emulator_err_t error = emulator->load_memory(code_address, image_buffer, prot_all);

		const auto end_time = std::chrono::high_resolution_clock::now();

		const auto time_taken = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

		spdlog::info("time taken: {} milliseconds", time_taken.count());

		error.throw_if("memory loading");

		error = emulator->hook_instruction(x86::insn::cpuid,
			[emulator]() -> bool
			{
				constexpr std::uint64_t new_rax = 0x1337;

				std::uint64_t rip = 0;

				(void)emulator->read_register(x86::reg::rip, &rip);
				(void)emulator->write_register(x86::reg::rax, &new_rax);

				spdlog::info("cpuid executed at 0x{:X}", rip);

				return true;
			},
			code_address,
			code_end_address
		).error_or({});

		error.throw_if("instruction hook attach");

		error = emulator->hook_basic_block(
			[emulator]()
			{
				std::uint64_t rip = 0;
				std::uint64_t rax = 0;

				(void)emulator->read_register(x86::reg::rip, &rip);
				(void)emulator->read_register(x86::reg::rax, &rax);

				spdlog::info("basic block executed at 0x{:X} (rax=0x{:X})", rip, rax);
			},
			code_address,
			code_end_address
		).error_or({});

		error.throw_if("basic block hook attach");

		error = emulator->hook_invalid_memory(
			[emulator](const emulator_t::address_type faulting_address, const protection_t access) -> bool
			{
				std::uint64_t rip = 0;

				(void)emulator->read_register(x86::reg::rip, &rip);

				spdlog::info("instruction at 0x{:X} access invalid memory address 0x{:X} with access type of {}", rip, faulting_address, static_cast<std::uint32_t>(access));

				return false;
			},
			prot_all,
			emulator_t::default_start_address,
			emulator_t::default_end_address
		).error_or({});

		error.throw_if("invalid memory hook attach");

		error = emulator->run_at(entry_point_address, emulator_t::thread_return_address);

		std::uint64_t rip = 0;

		(void)emulator->read_register(x86::reg::rip, &rip);

		spdlog::info("emulation finished at rip=0x{:X}", rip);

		error.throw_if("emulation running");
	}
	catch (const std::exception& e)
	{
		spdlog::error(e.what());
	}

	return 0;
}
