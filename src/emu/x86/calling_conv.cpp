#include "calling_conv.hpp"
#include "../../kernel/thread_scheduler.hpp"

void x86_win_conv::set_arg(vcpu& cpu, thread& t, const std::size_t index, const std::uint64_t value) const
{
	if (index < std::size(arg_regs))
	{
		t.set_reg(cpu, arg_regs[index], value);
		return;
	}

	// The saved sp points at the return address enqueue() pushed, which stack_arg_off measures.
	const auto sp = t.get_reg(cpu, x86::rsp);
	t.proc()->addr_space()->write_mem(sp + stack_arg_off(index), value);
}

void x86_win_conv::set_ret_addr(vcpu& cpu, thread& t, const addr_t addr) const
{
	// x86 has no link register: the return address is pushed, so the saved sp moves with it.
	const auto rsp = t.get_reg(cpu, x86::rsp) - sizeof(addr_t);
	t.proc()->addr_space()->write_mem(rsp, addr);
	t.set_reg(cpu, x86::rsp, rsp);
}

std::uint64_t x86_win_conv::read_ret(vcpu& cpu, const thread& t) const
{
	return t.get_reg(cpu, x86::rax);
}

void x86_win_conv::set_ret(vcpu& cpu, thread& t, const std::uint64_t value) const
{
	t.set_reg(cpu, x86::rax, value);
}
