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

void arch::set_ret_addr(vcpu& cpu, const addr_t addr) const
{
	const auto rsp = cpu.reg(x86::rsp) - sizeof(addr_t);
	cpu.write_virt_mem(rsp, addr);
	cpu.reg(x86::rsp, rsp);
}

std::span<const reg_t> arch::regs() const
{
	static constexpr reg_t regs[] = {
		rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
		r8, r9, r10, r11, r12, r13, r14, r15,
		rip, rflags,
		xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7,
		xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15,
		cs, ss, gs,
	};
	return regs;
}

std::size_t arch::reg_size(reg_t r) const
{
	if (r >= xmm0 && r <= xmm15) return sizeof(xmm_t);
	if (r >= cs && r <= idtr) return sizeof(seg_reg);
	return sizeof(std::uint64_t);
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
	case 14: return cpu_exception::page_fault;
	default: return cpu_exception::other;
	}
}

addr_t arch::fault_addr(vcpu& cpu) const
{
	return cpu.reg(cr2);
}

}
