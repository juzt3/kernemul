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
	void set_ret(vcpu& cpu, thread& t, std::uint64_t value) const override;

	// The caller reserves 32 bytes above the return address for the first four
	// arguments whether or not it uses them, so the fifth is the first that
	// actually lives on the stack.
	static constexpr addr_t home_space_size = 0x20;

	// Where argument `index` sits relative to a stack pointer that is pointing
	// at the return address, which is where it points on entry to the callee.
	static constexpr addr_t stack_arg_off(const std::size_t index)
	{
		return sizeof(addr_t) + home_space_size
			+ (index - std::size(arg_regs)) * sizeof(addr_t);
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
		return cpu.reg(x86::rax);
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
		cpu.reg_write(x86::rax, buf, size);
	}
};
