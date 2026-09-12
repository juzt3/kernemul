#pragma once
#include "../calling_conv.hpp"
#include "arch.hpp"

// The Windows x64 convention: the first four integer arguments in rcx, rdx, r8,
// r9, the rest on the stack above the 32-byte home space the caller reserves,
// and the result in rax.
struct x86_win_conv : calling_conv
{
	static constexpr reg_t arg_regs[] = { x86::rcx, x86::rdx, x86::r8, x86::r9 };

	void set_arg(vcpu& cpu, thread& t, std::size_t index, std::uint64_t value) const override;

	void write_arg(vcpu& cpu, const std::size_t index, const std::uint64_t value) const override
	{
		if (index < std::size(arg_regs))
			cpu.reg(arg_regs[index], value);
	}

	std::uint64_t read_ret(vcpu& cpu) const override
	{
		return cpu.reg(x86::rax);
	}

protected:
	void arg_read(vcpu& cpu, const std::size_t index, void* buf, const std::size_t size) const override
	{
		if (index < std::size(arg_regs))
			cpu.reg_read(arg_regs[index], buf, size);
		else
			cpu.read_virt_mem(cpu.sp() + 0x08 * (index + 1), buf, size);
	}

	void ret_write(vcpu& cpu, const void* buf, const std::size_t size) const override
	{
		cpu.reg_write(x86::rax, buf, size);
	}
};
