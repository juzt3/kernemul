#pragma once
#include "../unicorn_base.hpp"
#include "arch.hpp"

namespace ia32 {
#include <ia32.hpp>
}

class x86_unicorn_vcpu final : public unicorn_vcpu_base
{
public:
	using unicorn_vcpu_base::unicorn_vcpu_base;

	void reg_read(reg_t reg, void* value, std::size_t size) override
	{
		if (const auto msr_id = to_msr(reg))
		{
			uc_x86_msr msr{ msr_id, 0 };
			uc_reg_read(uc_, UC_X86_REG_MSR, &msr);
			std::memcpy(value, &msr.value, std::min(size, sizeof(msr.value)));
			return;
		}
		if (is_seg_reg(reg))
		{
			uc_x86_mmr mmr{};
			uc_reg_read(uc_, to_uc_reg(reg), &mmr);

			if (const auto base_reg = to_uc_base_reg(reg); base_reg >= 0)
				uc_reg_read(uc_, base_reg, &mmr.base);

			const x86::seg_reg sr{ mmr.selector, mmr.base, mmr.limit, mmr.flags };
			std::memcpy(value, &sr, std::min(size, sizeof(sr)));
			return;
		}
		if (is_xmm_reg(reg))
		{
			x86::xmm_t tmp{};
			uc_reg_read(uc_, to_uc_reg(reg), &tmp);
			std::memcpy(value, &tmp, std::min(size, sizeof(tmp)));
			return;
		}
		std::uint64_t tmp{};
		uc_reg_read(uc_, to_uc_reg(reg), &tmp);
		std::memcpy(value, &tmp, std::min(size, sizeof(tmp)));
	}

	void reg_write(reg_t reg, const void* value, std::size_t size) override
	{
		if (const auto msr_id = to_msr(reg))
		{
			std::uint64_t val{};
			std::memcpy(&val, value, std::min(size, sizeof(val)));
			uc_x86_msr msr{ msr_id, val };
			uc_reg_write(uc_, UC_X86_REG_MSR, &msr);
			return;
		}
		if (is_seg_reg(reg))
		{
			x86::seg_reg sr{};
			std::memcpy(&sr, value, std::min(size, sizeof(sr)));
			uc_x86_mmr mmr{ sr.selector, sr.base, sr.limit, sr.flags };
			uc_reg_write(uc_, to_uc_reg(reg), &mmr);

			// Writing a selector loads the gdt descriptor over our base.
			if (const auto base_reg = to_uc_base_reg(reg); base_reg >= 0)
				uc_reg_write(uc_, base_reg, &sr.base);

			return;
		}
		if (is_xmm_reg(reg))
		{
			x86::xmm_t tmp{};
			std::memcpy(&tmp, value, std::min(size, sizeof(tmp)));
			uc_reg_write(uc_, to_uc_reg(reg), &tmp);
			return;
		}
		std::uint64_t tmp{};
		std::memcpy(&tmp, value, std::min(size, sizeof(tmp)));
		uc_reg_write(uc_, to_uc_reg(reg), &tmp);
	}

	static constexpr std::uint32_t to_msr(reg_t reg)
	{
		switch (reg)
		{
		case x86::efer:  return IA32_EFER;
		case x86::star:  return IA32_STAR;
		case x86::lstar: return IA32_LSTAR;
		case x86::cstar: return IA32_CSTAR;
		case x86::fmask: return IA32_FMASK;
		default: return 0;
		}
	}

	// Both of these classify by enum range, so the order of x86::regs matters.
	static constexpr bool is_seg_reg(reg_t reg)
	{
		return reg >= x86::cs && reg <= x86::idtr;
	}

	static constexpr bool is_xmm_reg(reg_t reg)
	{
		return reg >= x86::xmm0 && reg <= x86::xmm15;
	}

	static constexpr int to_uc_base_reg(reg_t reg)
	{
		switch (reg)
		{
		case x86::fs: return UC_X86_REG_FS_BASE;
		case x86::gs: return UC_X86_REG_GS_BASE;
		default: return -1;
		}
	}

	static constexpr int to_uc_reg(reg_t reg)
	{
		switch (reg)
		{
		case x86::rax:    return UC_X86_REG_RAX;
		case x86::rcx:    return UC_X86_REG_RCX;
		case x86::rdx:    return UC_X86_REG_RDX;
		case x86::rbx:    return UC_X86_REG_RBX;
		case x86::rsp:    return UC_X86_REG_RSP;
		case x86::rbp:    return UC_X86_REG_RBP;
		case x86::rsi:    return UC_X86_REG_RSI;
		case x86::rdi:    return UC_X86_REG_RDI;
		case x86::r8:     return UC_X86_REG_R8;
		case x86::r9:     return UC_X86_REG_R9;
		case x86::r10:    return UC_X86_REG_R10;
		case x86::r11:    return UC_X86_REG_R11;
		case x86::r12:    return UC_X86_REG_R12;
		case x86::r13:    return UC_X86_REG_R13;
		case x86::r14:    return UC_X86_REG_R14;
		case x86::r15:    return UC_X86_REG_R15;
		case x86::rip:    return UC_X86_REG_RIP;
		case x86::rflags: return UC_X86_REG_RFLAGS;
		case x86::cr0:    return UC_X86_REG_CR0;
		case x86::cr2:    return UC_X86_REG_CR2;
		case x86::cr3:    return UC_X86_REG_CR3;
		case x86::cr4:    return UC_X86_REG_CR4;
		case x86::cr8:    return UC_X86_REG_CR8;
		case x86::cs:     return UC_X86_REG_CS;
		case x86::ds:     return UC_X86_REG_DS;
		case x86::es:     return UC_X86_REG_ES;
		case x86::ss:     return UC_X86_REG_SS;
		case x86::fs:     return UC_X86_REG_FS;
		case x86::gs:     return UC_X86_REG_GS;
		case x86::tr:     return UC_X86_REG_TR;
		case x86::ldtr:   return UC_X86_REG_LDTR;
		case x86::gdtr:   return UC_X86_REG_GDTR;
		case x86::idtr:   return UC_X86_REG_IDTR;
		case x86::xmm0:   return UC_X86_REG_XMM0;
		case x86::xmm1:   return UC_X86_REG_XMM1;
		case x86::xmm2:   return UC_X86_REG_XMM2;
		case x86::xmm3:   return UC_X86_REG_XMM3;
		case x86::xmm4:   return UC_X86_REG_XMM4;
		case x86::xmm5:   return UC_X86_REG_XMM5;
		case x86::xmm6:   return UC_X86_REG_XMM6;
		case x86::xmm7:   return UC_X86_REG_XMM7;
		case x86::xmm8:   return UC_X86_REG_XMM8;
		case x86::xmm9:   return UC_X86_REG_XMM9;
		case x86::xmm10:  return UC_X86_REG_XMM10;
		case x86::xmm11:  return UC_X86_REG_XMM11;
		case x86::xmm12:  return UC_X86_REG_XMM12;
		case x86::xmm13:  return UC_X86_REG_XMM13;
		case x86::xmm14:  return UC_X86_REG_XMM14;
		case x86::xmm15:  return UC_X86_REG_XMM15;
		default: return -1;
		}
	}
};

class x86_unicorn_emu final : public unicorn_emu_base
{
public:
	explicit x86_unicorn_emu(std::shared_ptr<mmu> mem, std::shared_ptr<calling_conv> call_conv = {})
		:	unicorn_emu_base(std::make_shared<x86::arch>(), std::move(mem), std::move(call_conv)) { }

protected:
	uc_engine* open_engine() override
	{
		uc_engine* uc = nullptr;
		if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK)
			throw std::runtime_error("uc_open failed for x86-64");
		return uc;
	}

	std::shared_ptr<unicorn_vcpu_base> wrap_engine(uc_engine* uc, const std::size_t id) override
	{
		return std::make_shared<x86_unicorn_vcpu>(this, arch_, uc, id);
	}

	int to_uc_insn(hook_insn_t insn) const override
	{
		switch (insn)
		{
		case hook_insn_t::cpuid:   return UC_X86_INS_CPUID;
		case hook_insn_t::rdtsc:   return UC_X86_INS_RDTSC;
		case hook_insn_t::syscall: return UC_X86_INS_SYSCALL;
		default: return -1;
		}
	}
};
