#include "nt_debugger.hpp"
#include "nt_helpers.hpp"

#include "../../util/logs.hpp"

void initialize_ntoskrnl_debugger_state(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
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

static void handle_kd_change_option(const std::shared_ptr<emulator_t>& emulator)
{
	constexpr std::uint32_t status_debugger_inactive = 0xC0000354;

	THREAD_LOG("KdChangeOption called, returning STATUS_DEBUGGER_INACTIVE");

	write_nt_status(emulator, status_debugger_inactive);
}

static void handle_system_debug_control(const std::shared_ptr<emulator_t>& emulator)
{
	constexpr std::uint32_t status_debugger_inactive = 0xC0000354;

	THREAD_LOG("SystemDebugControl called, returning STATUS_DEBUGGER_INACTIVE");

	write_nt_status(emulator, status_debugger_inactive);
}

static void handle_kd_system_debug_control(const std::shared_ptr<emulator_t>& emulator)
{
	constexpr std::uint32_t status_access_denied = 0xC0000022;

	THREAD_LOG("KdSystemDebugControl called, returning STATUS_ACCESS_DENIED");

	write_nt_status(emulator, status_access_denied);
}

static void handle_dbg_set_debug_print_callback(const std::shared_ptr<emulator_t>& emulator)
{
	THREAD_LOG("DbgSetDebugPrintCallback called, returning STATUS_SUCCESS");

	write_nt_success(emulator);
}

void redirect_ntoskrnl_debugger_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_kd_change_option>(emulator, mapped_image, "KdChangeOption");

	redirect_handler<handle_system_debug_control>(emulator, mapped_image, "ZwSystemDebugControl");
	redirect_handler<handle_system_debug_control>(emulator, mapped_image, "NtSystemDebugControl");

	redirect_handler<handle_kd_system_debug_control>(emulator, mapped_image, "KdSystemDebugControl");

	redirect_handler<handle_dbg_set_debug_print_callback>(emulator, mapped_image, "DbgSetDebugPrintCallback");
}
