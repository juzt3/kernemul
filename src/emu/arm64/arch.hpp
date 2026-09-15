#pragma once
#include "../arch.hpp"
#include <cstdint>

namespace arm64
{
	// A 128-bit SIMD/FP register. Kept 16-byte aligned so it can be memcpy'd
	// straight in and out of reg_val.
	struct alignas(16) vec_t
	{
		std::uint64_t low{};
		std::uint64_t high{};
	};

	// System registers reachable through UC_ARM64_REG_CP_REG are addressed by
	// their (op0, op1, crn, crm, op2) encoding rather than a named enum.
	struct sys_reg_enc
	{
		std::uint32_t op0, op1, crn, crm, op2;
	};

	enum regs : reg_t
	{
		// general purpose; x29 is the frame pointer, x30 the link register
		x0,  x1,  x2,  x3,  x4,  x5,  x6,  x7,
		x8,  x9,  x10, x11, x12, x13, x14, x15,
		x16, x17, x18, x19, x20, x21, x22, x23,
		x24, x25, x26, x27, x28, x29, x30,

		sp, pc, pstate,

		// system registers Unicorn names directly
		tpidr_el0, tpidrro_el0, tpidr_el1,
		ttbr0_el1, ttbr1_el1,
		mair_el1, cpacr_el1, vbar_el1,
		esr_el1, far_el1, elr_el1,
		fpcr, fpsr,

		// system registers that only exist behind UC_ARM64_REG_CP_REG. Kept in
		// one contiguous run so the backend can classify them by range.
		sctlr_el1, tcr_el1, spsr_el1, scr_el3, hcr_el2,

		// The feature registers. Privileged, but usermode reads them anyway --
		// see arm64_win_emulator::read_sysreg.
		id_aa64pfr0_el1, id_aa64isar0_el1, id_aa64isar1_el1, id_aa64mmfr0_el1,

		sys_first = sctlr_el1,
		sys_last  = id_aa64mmfr0_el1,

		// 128-bit vector registers, contiguous and last for the same reason
		q0,  q1,  q2,  q3,  q4,  q5,  q6,  q7,
		q8,  q9,  q10, q11, q12, q13, q14, q15,
		q16, q17, q18, q19, q20, q21, q22, q23,
		q24, q25, q26, q27, q28, q29, q30, q31,
	};

	constexpr reg_t fp = x29;
	constexpr reg_t lr = x30;

	// Encodings for the registers behind CP_REG (Arm ARM D17.2).
	constexpr sys_reg_enc sys_enc(const reg_t r)
	{
		switch (r)
		{
		case sctlr_el1: return { 3, 0, 1, 0, 0 };
		case tcr_el1:   return { 3, 0, 2, 0, 2 };
		case spsr_el1:  return { 3, 0, 4, 0, 0 };
		case scr_el3:   return { 3, 6, 1, 1, 0 };
		case hcr_el2:   return { 3, 4, 1, 1, 0 };

		case id_aa64pfr0_el1:  return { 3, 0, 0, 4, 0 };
		case id_aa64isar0_el1: return { 3, 0, 0, 6, 0 };
		case id_aa64isar1_el1: return { 3, 0, 0, 6, 1 };
		case id_aa64mmfr0_el1: return { 3, 0, 0, 7, 0 };

		default:        return { 0, 0, 0, 0, 0 };
		}
	}

	struct arch : ::arch
	{
		reg_t pc() const override { return arm64::pc; }
		reg_t sp() const override { return arm64::sp; }
		addr_t ret_addr(vcpu& cpu) const override;
		void set_ret_addr(vcpu& cpu, addr_t addr) const override;
		void init_vcpu(vcpu& cpu) override;
		std::span<const reg_t> regs() const override;
		std::size_t reg_size(reg_t r) const override;
		cpu_exception intr_to_excp(int vector) const override;
		addr_t fault_addr(vcpu& cpu) const override;
	};
}
