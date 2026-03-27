#include "nt_debugger.hpp"
#include "nt_helpers.hpp"

#include "../../util/logs.hpp"

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

			THREAD_LOG("KdChangeOption called, returning STATUS_DEBUGGER_INACTIVE");

			write_nt_status(emulator, status_debugger_inactive);
		},
		mapped_image,
		"KdChangeOption"
	);

	redirect_function(
		[emulator]
		{
			constexpr std::uint32_t status_debugger_inactive = 0xC0000354;

			THREAD_LOG("ZwSystemDebugControl called, returning STATUS_DEBUGGER_INACTIVE");

			write_nt_status(emulator, status_debugger_inactive);
		},
		mapped_image,
		"ZwSystemDebugControl"
	);

	redirect_function(
		[emulator]
		{
			constexpr std::uint32_t status_debugger_inactive = 0xC0000354;

			THREAD_LOG("NtSystemDebugControl called, returning STATUS_DEBUGGER_INACTIVE");

			write_nt_status(emulator, status_debugger_inactive);
		},
		mapped_image,
		"NtSystemDebugControl"
	);

	redirect_function(
		[emulator]
		{
			constexpr std::uint32_t status_access_denied = 0xC0000022;

			THREAD_LOG("KdSystemDebugControl called, returning STATUS_ACCESS_DENIED");

			write_nt_status(emulator, status_access_denied);
		},
		mapped_image,
		"KdSystemDebugControl"
	);
}
