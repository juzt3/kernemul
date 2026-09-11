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

	struct alignas(16) xmm_t
	{
		std::uint64_t low{};
		std::uint64_t high{};
	};

	enum regs : reg_t
	{
		rax, rcx, rdx, rbx,
		rsp, rbp, rsi, rdi,
		r8, r9, r10, r11,
		r12, r13, r14, r15,
		rip, rflags,
		cr0, cr3, cr4, efer,
		star, lstar, cstar, fmask,
		cs, ds, es, ss, fs, gs,
		tr, ldtr, gdtr, idtr,
		xmm0, xmm1, xmm2, xmm3,
		xmm4, xmm5, xmm6, xmm7,
		xmm8, xmm9, xmm10, xmm11,
		xmm12, xmm13, xmm14, xmm15,
	};

	struct arch : ::arch
	{
		reg_t pc() const override { return rip; }
		reg_t sp() const override { return rsp; }
		addr_t ret_addr(vcpu& cpu) const override;
		void init_vcpu(vcpu& cpu) override;
		std::span<const reg_t> regs() const override;
		std::size_t reg_size(reg_t r) const override;
		cpu_exception intr_to_excp(int vector) const override;
	};
}
