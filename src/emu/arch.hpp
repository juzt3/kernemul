#pragma once
#include "defs.hpp"
#include <cstddef>

using reg_t = int;

struct arch
{
	virtual ~arch() = default;
	virtual reg_t pc() const = 0;
};

namespace x86
{
	enum regs : reg_t
	{
		rax, rcx, rdx, rbx,
		rsp, rbp, rsi, rdi,
		r8, r9, r10, r11,
		r12, r13, r14, r15,
		rip, rflags,
	};

	struct arch : ::arch
	{
		reg_t pc() const override { return rip; }
	};
}
