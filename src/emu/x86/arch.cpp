#include "arch.hpp"
#include "../emu.hpp"

namespace x86
{

addr_t arch::ret_addr(vcpu& cpu) const
{
	const auto ret = cpu.read_virt_mem<addr_t>(cpu.reg(rsp));
	cpu.reg(rsp, cpu.reg(rsp) + sizeof(addr_t));
	return ret;
}

std::span<const reg_t> arch::regs() const
{
	static constexpr reg_t regs[] = {
		rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
		r8, r9, r10, r11, r12, r13, r14, r15,
		rip, rflags
	};
	return regs;
}

void arch::init_vcpu(vcpu&)
{
}

cpu_exception arch::intr_to_excp(int vector) const
{
	switch (vector)
	{
	case 0:  return cpu_exception::divide_by_zero;
	case 1:  return cpu_exception::debug;
	case 3:  return cpu_exception::breakpoint;
	case 6:  return cpu_exception::illegal_instruction;
	default: return cpu_exception::other;
	}
}

}
