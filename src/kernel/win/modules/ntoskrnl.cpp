#include "ntoskrnl.hpp"
#include "../../kernel.hpp"

static std::string read_guest_string(vcpu& cpu, addr_t addr)
{
	std::string result;
	char c;

	for (std::size_t i = 0; i < 512; ++i)
	{
		c = cpu.read_virt_mem<char>(addr + i);

		if (c == '\0')
			break;

		result += c;
	}

	return result;
}

void modules::register_ntoskrnl(kernel_state& state, proc_module& mod)
{
	state.redirect(mod, "DbgPrintEx",
		[](vcpu& cpu, std::uint32_t component_id, std::uint32_t level, addr_t format_addr) -> std::uint32_t
		{
			const auto format = read_guest_string(cpu, format_addr);
			LOG_INFO("DbgPrintEx called (component={}, level={}) : {}", component_id, level, format);
			return 0;
		});
}
