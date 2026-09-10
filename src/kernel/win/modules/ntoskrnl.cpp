#include "ntoskrnl.hpp"
#include "../../kernel.hpp"

void modules::register_ntoskrnl(kernel_state& state, proc_module& mod)
{
	state.redirect(mod, "DbgPrintEx",
		[](vcpu& cpu, std::uint32_t component_id, std::uint32_t level, std::string format) -> std::uint32_t
		{
			LOG_INFO("DbgPrintEx called (component={}, level={}) : {}", component_id, level, format);
			return 0;
		});
}
