#include "ntoskrnl.hpp"
#include "../../kernel.hpp"
#include "../../../util/format.hpp"

void modules::register_ntoskrnl(kernel_state& state, proc_module& mod)
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
}
