#include "nt_debugger.hpp"
#include "nt_helpers.hpp"

#include <spdlog/spdlog.h>

void initialize_ntoskrnl_debugger_state(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	if (const auto addr = mapped_image.find_symbol("KdDebuggerNotPresent"))
	{
		constexpr std::uint8_t value = 1;

		const emulator_err_t error = emulator->write_virtual_memory(*addr, &value, sizeof(value));
		error.throw_if("write KdDebuggerNotPresent");
	}

	if (const auto addr = mapped_image.find_symbol("KdDebuggerEnabled"))
	{
		constexpr std::uint8_t value = 0;

		const emulator_err_t error = emulator->write_virtual_memory(*addr, &value, sizeof(value));
		error.throw_if("write KdDebuggerEnabled");
	}

	if (const auto addr = mapped_image.find_symbol("KdEnteredDebugger"))
	{
		constexpr std::uint8_t value = 0;

		const emulator_err_t error = emulator->write_virtual_memory(*addr, &value, sizeof(value));
		error.throw_if("write KdEnteredDebugger");
	}
}

void redirect_ntoskrnl_debugger_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			constexpr std::uint32_t status_debugger_inactive = 0xC0000354;

			spdlog::info("KdChangeOption called, returning STATUS_DEBUGGER_INACTIVE");

			write_nt_status(emulator, status_debugger_inactive);
		},
		mapped_image,
		"KdChangeOption"
	);
}
