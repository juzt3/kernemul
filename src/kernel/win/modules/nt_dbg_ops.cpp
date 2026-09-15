#include "nt_dbg_ops.hpp"
#include "../win_kernel.hpp"
#include "../status.hpp"
#include "../../../util/format.hpp"

// Everything a driver prints goes to the emulator log, which is the only debugger there is.
void modules::register_ntoskrnl_dbg_ops(win_kernel_state& state, proc_module& mod)
{
	state.redirect(mod, "DbgPrint",
		[](vcpu& cpu, std::string format) -> std::uint32_t
		{
			const auto msg = guest::vsprintf(*cpu.curr_addr_space(), format, varargs(cpu, 1));

			THREAD_LOG_INFO("DbgPrint: {}", msg);
			return 0;
		});

	state.redirect(mod, "DbgPrintEx",
		[](vcpu& cpu, std::uint32_t component_id, std::uint32_t level, std::string format) -> std::uint32_t
		{
			const auto msg = guest::vsprintf(*cpu.curr_addr_space(), format, varargs(cpu, 3));

			THREAD_LOG_INFO("DbgPrintEx (component={}, level={}) : {}", component_id, level, msg);
			return 0;
		});

	state.redirect(mod, "KdChangeOption",
		[](vcpu&, const std::uint32_t option, const std::uint32_t in_buffer_bytes,
			const addr_t in_buffer, const std::uint32_t out_buffer_bytes,
			const addr_t out_buffer, emu_object<std::uint32_t> out_buffer_needed) -> NTSTATUS
		{
			if (out_buffer_needed)
				out_buffer_needed.write(0);

			THREAD_LOG_WARN("KdChangeOption(option={}, in=0x{:X}/{}, out=0x{:X}/{}): no kernel "
				"debugger is attached to hold an option",
				option, in_buffer, in_buffer_bytes, out_buffer, out_buffer_bytes);

			return STATUS_DEBUGGER_INACTIVE;
		});

	auto system_debug_control = [](vcpu&, const std::uint32_t command,
		const addr_t input_buffer, const std::uint32_t input_buffer_length,
		const addr_t output_buffer, const std::uint32_t output_buffer_length,
		emu_object<std::uint32_t> return_length) -> NTSTATUS
	{
		if (return_length)
			return_length.write(0);

		THREAD_LOG_WARN("KdSystemDebugControl(command={}, in=0x{:X}/{}, out=0x{:X}/{}): no kernel "
			"debugger is attached",
			command, input_buffer, input_buffer_length, output_buffer, output_buffer_length);

		// What the real one returns without a debugger: the privilege is the check that fails.
		return STATUS_ACCESS_DENIED;
	};

	state.redirect(mod, "KdSystemDebugControl", system_debug_control);
	state.redirect_ntzw(mod, "SystemDebugControl", system_debug_control);

	state.redirect(mod, "DbgSetDebugPrintCallback",
		[](vcpu&, const addr_t debug_print_callback, const bool enable) -> NTSTATUS
		{
			THREAD_LOG_WARN("DbgSetDebugPrintCallback(0x{:X}, enable={}): registered, but DbgPrint "
				"output goes to the emulator log and nothing forwards it on",
				debug_print_callback, enable);

			// The registration succeeds: a driver told it failed treats its own logging as broken.
			return STATUS_SUCCESS;
		});
}
