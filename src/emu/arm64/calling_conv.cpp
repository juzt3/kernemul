#include "calling_conv.hpp"
#include "../../kernel/thread_scheduler.hpp"

void arm64_win_conv::set_arg(vcpu& cpu, thread& t, const std::size_t index, const std::uint64_t value) const
{
	if (index < std::size(arg_regs))
		t.set_reg(cpu, arg_regs[index], value);
}

void arm64_win_conv::set_ret_addr(vcpu& cpu, thread& t, const addr_t addr) const
{
	t.set_reg(cpu, arm64::lr, addr);
}

std::uint64_t arm64_win_conv::read_ret(vcpu& cpu, const thread& t) const
{
	return t.get_reg(cpu, arm64::x0);
}
