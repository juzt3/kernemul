#include "nt_debugger.hpp"

#include <spdlog/spdlog.h>

void initialize_ntoskrnl_debugger_state(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image)
{
	if (const auto addr = mapped_image.find_symbol("KdDebuggerNotPresent"))
	{
		constexpr std::uint8_t value = 1;
		emulator_err_t error = emulator->write_virtual_memory(*addr, &value, sizeof(value));
		error.throw_if("write KdDebuggerNotPresent");

		spdlog::info("set KdDebuggerNotPresent (0x{:X}) to TRUE", *addr);
	}

	if (const auto addr = mapped_image.find_symbol("KdDebuggerEnabled"))
	{
		constexpr std::uint8_t value = 0;
		emulator_err_t error = emulator->write_virtual_memory(*addr, &value, sizeof(value));
		error.throw_if("write KdDebuggerEnabled");

		spdlog::info("set KdDebuggerEnabled (0x{:X}) to FALSE", *addr);
	}
}
