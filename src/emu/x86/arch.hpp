#pragma once
#include "../arch.hpp"
#include <cstdint>

namespace x86
{
	struct seg_reg
	{
		std::uint16_t selector = 0;
		std::uint64_t base = 0;
		std::uint32_t limit = 0;
		std::uint32_t flags = 0;
	};

	enum regs : reg_t
	{
		rax, rcx, rdx, rbx,
		rsp, rbp, rsi, rdi,
		r8, r9, r10, r11,
		r12, r13, r14, r15,
		rip, rflags,
		cr0, cr3, cr4, efer,
		cs, ds, es, ss, fs, gs,
		tr, ldtr, gdtr, idtr,
	};

	struct arch : ::arch
	{
		reg_t pc() const override { return rip; }
		void init_vcpu(vcpu& cpu) override;
	};
}
