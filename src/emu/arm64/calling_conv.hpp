#pragma once
#include "../calling_conv.hpp"
#include "arch.hpp"

// AAPCS64, which Windows on ARM follows: the first eight integer arguments in
// x0-x7, the rest on the stack with no home space reserved, and the result in
// x0. SP is 16-byte aligned at every public interface.
struct arm64_win_conv : calling_conv
{
	static constexpr reg_t arg_regs[] = {
		arm64::x0, arm64::x1, arm64::x2, arm64::x3,
		arm64::x4, arm64::x5, arm64::x6, arm64::x7,
	};

	void set_arg(vcpu& cpu, thread& t, std::size_t index, std::uint64_t value) const override;
	void set_ret(vcpu& cpu, thread& t, std::uint64_t value) const override;

	// AAPCS64 reserves no home space, so the ninth argument is the first thing
	// on the stack and sits right at the stack pointer on entry to the callee.
	static constexpr addr_t stack_arg_off(const std::size_t index)
	{
		return (index - std::size(arg_regs)) * sizeof(addr_t);
	}

	void write_arg(vcpu& cpu, const std::size_t index, const std::uint64_t value) const override
	{
		if (index < std::size(arg_regs))
			cpu.reg(arg_regs[index], value);
		else
			cpu.write_virt_mem(cpu.sp() + stack_arg_off(index), value);
	}

	std::uint64_t read_ret(vcpu& cpu) const override
	{
		return cpu.reg(arm64::x0);
	}

	void set_ret_addr(vcpu& cpu, thread& t, addr_t addr) const override;
	std::uint64_t read_ret(vcpu& cpu, const thread& t) const override;

protected:
	void arg_read(vcpu& cpu, const std::size_t index, void* buf, const std::size_t size) const override
	{
		if (index < std::size(arg_regs))
			cpu.reg_read(arg_regs[index], buf, size);
		else
			cpu.read_virt_mem(cpu.sp() + stack_arg_off(index), buf, size);
	}

	void ret_write(vcpu& cpu, const void* buf, const std::size_t size) const override
	{
		cpu.reg_write(arm64::x0, buf, size);
	}
};
