#pragma once
#include "../arch.hpp"

namespace x86
{
	enum regs : reg_t
	{
		rax, rcx, rdx, rbx,
		rsp, rbp, rsi, rdi,
		r8, r9, r10, r11,
		r12, r13, r14, r15,
		rip, rflags,
		cr0, cr3, cr4, efer,
	};

	struct arch : ::arch
	{
		reg_t pc() const override { return rip; }
	};
}
