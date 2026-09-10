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
	state.redirect(mod, "DbgPrintEx", [](vcpu& cpu)
	{
		const auto component_id = cpu.reg<x86::rcx, std::uint32_t>();
		const auto level = cpu.reg<x86::rdx, std::uint32_t>();
		const auto format_addr = cpu.reg(x86::r8);
		const auto format = read_guest_string(cpu, format_addr);

		LOG_INFO("DbgPrintEx called (component={}, level={}) : {}", component_id, level, format);

		cpu.reg(x86::rax, 0ull);
	});
}
