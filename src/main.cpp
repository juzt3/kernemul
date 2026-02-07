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
		emulator_t emulator;

		const emulator_t::address_type code_address = nt_headers->optional_header.image_base;
		const emulator_t::address_type entry_point_address = code_address + nt_headers->optional_header.address_of_entry_point;
	
		const auto image_start = pe_image->as<const std::uint8_t*>();
		const std::span image_buffer(image_start, image_start + nt_headers->optional_header.size_of_image);

		emulator_err_t error = emulator.load_memory(code_address, image_buffer, UC_PROT_ALL);

		error.throw_if("memory loading");

		error = emulator.run_at(entry_point_address, emulator_t::thread_return_address);

		error.throw_if("emulation running");
	}
	catch (const std::exception& e)
	{
		spdlog::error(e.what());
	}

	return 0;
}
