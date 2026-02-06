#include <spdlog/spdlog.h>

#include "emulator/emulator.hpp"

std::int32_t main()
{
	spdlog::info("emulation");

	try
	{
		const emulator_t emulator;

		constexpr emulator_t::address_type code_address = 0x2000;
		constexpr emulator_t::address_type code_size = 0x1000;

		emulator_err_t error = emulator.map_memory(code_address, code_size, UC_PROT_ALL);

		error.throw_if("memory mapping");

		constexpr std::array<std::uint8_t, 8> stub = { 0x48, 0xC7, 0xC0, 0x37, 0x13, 0x00, 0x00, 0xC3 };

		error = emulator.write_memory(code_address, stub);

		error.throw_if("memory writing");

		error = emulator.run_at(code_address, code_address + 7);

		error.throw_if("emulation running");
	}
	catch (const std::exception& e)
	{
		spdlog::error(e.what());
	}

	return 0;
}
