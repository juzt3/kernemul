#include "emulator/emulator.hpp"

#include <portable_executable/file.hpp>
#include <spdlog/spdlog.h>

#include "portable_executable/image.hpp"

std::int32_t main()
{
	spdlog::info("emulation");

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
		const auto emulator = std::make_shared<emulator_t>();

		const emulator_t::address_type code_address = nt_headers->optional_header.image_base;
		const emulator_t::address_type entry_point_address = code_address + nt_headers->optional_header.address_of_entry_point;

		const auto image_start = pe_image->as<const std::uint8_t*>();
		const std::span image_buffer(image_start, image_start + nt_headers->optional_header.size_of_image);

		emulator_err_t error = emulator->load_memory(code_address, image_buffer, UC_PROT_ALL);

		error.throw_if("memory loading");

		error = emulator->hook_instruction(x86::instruction::cpuid,
			[](const emulator_t& ee) -> bool
			{
				std::uint64_t rip = 0;
				constexpr std::uint64_t new_rax = 0x1337;

				(void)ee.read_program_counter(&rip);
				(void)ee.write_register(x86::reg::rax, &new_rax);

				spdlog::info("cpuid executed at 0x{:X}", rip);

				return true;
			}
		);

		error.throw_if("instruction hook attach");

		error = emulator->hook_basic_block(
			[]([[maybe_unused]] const emulator_t& ee, const std::uint64_t address)
			{
				spdlog::info("basic block executed at 0x{:X}", address);
			}
		);

		error.throw_if("basic block hook attach");

		error = emulator->hook_code(
			[](const emulator_t& ee, const std::uint64_t address)
			{
				std::uint64_t rax = 0;

				(void)ee.read_register(x86::reg::rax, &rax);

				spdlog::info("rax: 0x{:X} at 0x{:X}", rax, address);
			},
			0x140001000,
			0x14000103D
		);

		error.throw_if("code hook attach");

		error = emulator->run_at(entry_point_address, emulator_t::thread_return_address);

		error.throw_if("emulation running");
	}
	catch (const std::exception& e)
	{
		spdlog::error(e.what());
	}

	return 0;
}
