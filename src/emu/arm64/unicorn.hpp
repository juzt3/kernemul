#pragma once
#include "../unicorn_base.hpp"
#include "arch.hpp"

#include <cstring>

class arm64_unicorn_vcpu final : public unicorn_vcpu_base
{
public:
	using unicorn_vcpu_base::unicorn_vcpu_base;

	void reg_read(reg_t reg, void* value, std::size_t size) override
	{
		if (is_cp_reg(reg))
		{
			const auto e = arm64::sys_enc(reg);
			uc_arm64_cp_reg cp{ e.crn, e.crm, e.op0, e.op1, e.op2, 0 };
			uc_reg_read(uc_, UC_ARM64_REG_CP_REG, &cp);
			std::memcpy(value, &cp.val, std::min(size, sizeof(cp.val)));
			return;
		}
		if (is_vec_reg(reg))
		{
			arm64::vec_t tmp{};
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
		if (is_cp_reg(reg))
		{
			std::uint64_t val{};
			std::memcpy(&val, value, std::min(size, sizeof(val)));
			const auto e = arm64::sys_enc(reg);
			uc_arm64_cp_reg cp{ e.crn, e.crm, e.op0, e.op1, e.op2, val };
			uc_reg_write(uc_, UC_ARM64_REG_CP_REG, &cp);
			return;
		}
		if (is_vec_reg(reg))
		{
			arm64::vec_t tmp{};
			std::memcpy(&tmp, value, std::min(size, sizeof(tmp)));
			uc_reg_write(uc_, to_uc_reg(reg), &tmp);
			return;
		}
		std::uint64_t tmp{};
		std::memcpy(&tmp, value, std::min(size, sizeof(tmp)));
		uc_reg_write(uc_, to_uc_reg(reg), &tmp);

		if (reg == arm64::pstate)
			rebuild_hflags();
	}

	// Unicorn's PSTATE write does not rebuild QEMU's cached hflags; only the CP_REG path does.
	void rebuild_hflags()
	{
		std::uint64_t sctlr{};
		reg_read(arm64::sctlr_el1, &sctlr, sizeof(sctlr));
		reg_write(arm64::sctlr_el1, &sctlr, sizeof(sctlr));
	}

	static constexpr bool is_cp_reg(reg_t reg)
	{
		return reg >= arm64::sys_first && reg <= arm64::sys_last;
	}

	static constexpr bool is_vec_reg(reg_t reg)
	{
		return reg >= arm64::q0 && reg <= arm64::q31;
	}

	static constexpr int to_uc_reg(reg_t reg)
	{
		// X29/X30 sit apart from the contiguous X0-X28 run in uc_arm64_reg.
		if (reg >= arm64::x0 && reg <= arm64::x28)
			return UC_ARM64_REG_X0 + (reg - arm64::x0);

		if (reg >= arm64::q0 && reg <= arm64::q31)
			return UC_ARM64_REG_Q0 + (reg - arm64::q0);

		switch (reg)
		{
		case arm64::x29:          return UC_ARM64_REG_X29;
		case arm64::x30:          return UC_ARM64_REG_X30;
		case arm64::sp:           return UC_ARM64_REG_SP;
		case arm64::pc:           return UC_ARM64_REG_PC;
		case arm64::pstate:       return UC_ARM64_REG_PSTATE;
		case arm64::tpidr_el0:    return UC_ARM64_REG_TPIDR_EL0;
		case arm64::tpidrro_el0:  return UC_ARM64_REG_TPIDRRO_EL0;
		case arm64::tpidr_el1:    return UC_ARM64_REG_TPIDR_EL1;
		case arm64::ttbr0_el1:    return UC_ARM64_REG_TTBR0_EL1;
		case arm64::ttbr1_el1:    return UC_ARM64_REG_TTBR1_EL1;
		case arm64::mair_el1:     return UC_ARM64_REG_MAIR_EL1;
		case arm64::cpacr_el1:    return UC_ARM64_REG_CPACR_EL1;
		case arm64::vbar_el1:     return UC_ARM64_REG_VBAR_EL1;
		case arm64::esr_el1:      return UC_ARM64_REG_ESR_EL1;
		case arm64::far_el1:      return UC_ARM64_REG_FAR_EL1;
		case arm64::elr_el1:      return UC_ARM64_REG_ELR_EL1;
		case arm64::fpcr:         return UC_ARM64_REG_FPCR;
		case arm64::fpsr:         return UC_ARM64_REG_FPSR;
		default: return -1;
		}
	}
};

class arm64_unicorn_emu final : public unicorn_emu_base
{
public:
	explicit arm64_unicorn_emu(std::shared_ptr<mmu> mem, std::shared_ptr<calling_conv> call_conv = {})
		:	unicorn_emu_base(std::make_shared<arm64::arch>(), std::move(mem), std::move(call_conv)) { }

protected:
	uc_engine* open_engine() override
	{
		uc_engine* uc = nullptr;
		if (uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc) != UC_ERR_OK)
			throw std::runtime_error("uc_open failed for aarch64");

		// MSVC targets ARMv8.1 and emits casal; the default Cortex-A57 has no LSE atomics.
		if (uc_ctl_set_cpu_model(uc, UC_CPU_ARM64_MAX) != UC_ERR_OK)
		{
			uc_close(uc);
			throw std::runtime_error("failed to select the aarch64 max cpu model");
		}

		return uc;
	}

	std::shared_ptr<unicorn_vcpu_base> wrap_engine(uc_engine* uc, const std::size_t id) override
	{
		return std::make_shared<arm64_unicorn_vcpu>(this, arch_, uc, id);
	}

	int to_uc_insn(hook_insn_t) const override
	{
		// Unicorn only hooks MRS/MSR/SYS/SYSL here, none of which match an entry in hook_insn_t.
		return -1;
	}

	int insn_as_intr(const hook_insn_t insn) const override
	{
		// SVC raises EXCP_SWI (target/arm/cpu.h), served from the interrupt hook.
		constexpr int excp_swi = 2;
		return insn == hook_insn_t::syscall ? excp_swi : -1;
	}

	addr_t insn_as_intr_len() const override { return 4; }
};
