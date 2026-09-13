#include "ntoskrnl.hpp"
#include "../../kernel.hpp"
#include "../../../util/format.hpp"

void modules::register_ntoskrnl(kernel_state& state, proc_module& mod)
{
	state.redirect(mod, "DbgPrint",
		[](vcpu& cpu, std::string format) -> std::uint32_t
		{
			std::size_t arg_idx = 1;
			auto& space = *cpu.curr_addr_space();
			const auto& conv = *cpu.emu()->call_conv();
			const auto msg = guest::vsprintf(space, format, [&]() -> std::uint64_t
			{
				return conv.arg<std::uint64_t>(cpu, arg_idx++);
			});

			THREAD_LOG_INFO("DbgPrint: {}", msg);
			return 0;
		});

	state.redirect(mod, "DbgPrintEx",
		[](vcpu& cpu, std::uint32_t component_id, std::uint32_t level, std::string format) -> std::uint32_t
		{
			std::size_t arg_idx = 3;
			auto& space = *cpu.curr_addr_space();
			const auto& conv = *cpu.emu()->call_conv();
			const auto msg = guest::vsprintf(space, format, [&]() -> std::uint64_t
			{
				return conv.arg<std::uint64_t>(cpu, arg_idx++);
			});

			THREAD_LOG_INFO("DbgPrintEx (component={}, level={}) : {}", component_id, level, msg);
			return 0;
		});
}
