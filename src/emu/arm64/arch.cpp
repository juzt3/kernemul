#include "arch.hpp"
#include "../emu.hpp"

namespace arm64
{

addr_t arch::ret_addr(vcpu& cpu) const
{
	// AArch64 keeps the return address in the link register, so unlike x86
	// there is nothing to pop -- the stack is untouched.
	return cpu.reg(lr);
}

void arch::set_ret_addr(vcpu& cpu, const addr_t addr) const
{
	cpu.reg(lr, addr);
}

std::span<const reg_t> arch::regs() const
{
	// The set a thread context is saved from and restored to. tpidr_el0 is in
	// here because it holds the TEB, which is per thread.
	static constexpr reg_t regs[] = {
		x0,  x1,  x2,  x3,  x4,  x5,  x6,  x7,
		x8,  x9,  x10, x11, x12, x13, x14, x15,
		x16, x17, x18, x19, x20, x21, x22, x23,
		x24, x25, x26, x27, x28, x29, x30,
		arm64::sp, arm64::pc, pstate, tpidr_el0,
		q0,  q1,  q2,  q3,  q4,  q5,  q6,  q7,
		q8,  q9,  q10, q11, q12, q13, q14, q15,
		q16, q17, q18, q19, q20, q21, q22, q23,
		q24, q25, q26, q27, q28, q29, q30, q31,
	};
	return regs;
}

std::size_t arch::reg_size(const reg_t r) const
{
	if (r >= q0 && r <= q31) return sizeof(vec_t);
	return sizeof(std::uint64_t);
}

void arch::init_vcpu(vcpu& cpu)
{
	// QEMU resets an AArch64 core into the highest implemented exception
	// level, and every CPU model Unicorn exposes implements EL2 and EL3 -- so
	// without this the core runs at EL3, where translation is governed by
	// TTBR0_EL3 and SCTLR_EL3 and the EL1 registers the MMU configures are
	// simply ignored. Drop to EL1h (EL1 using SP_EL1), which is where a
	// Windows kernel driver believes it is running.
	//   PSTATE.M[3:0] = 0b0101 : EL1, SP_ELx
	//   DAIF          = 0xF<<6 : interrupts masked, since nothing delivers any
	//
	// Getting to EL1 is not enough on its own: the core also comes out of
	// reset in Secure state, and QEMU aliases sctlr_el[1] onto sctlr_ns while
	// a banked write from Secure state lands in sctlr_s. The EL1 translation
	// regime would then read an SCTLR whose M bit is still clear, translation
	// would stay off, and every guest VA would be treated as a physical
	// address. So drop to Non-secure first, while still at EL3.
	//   SCR_EL3.NS  (bit 0)  : lower levels are Non-secure
	//   SCR_EL3     (bits 4,5): RES1
	//   SCR_EL3.RW  (bit 10) : EL1 is AArch64
	constexpr std::uint64_t scr_ns = 1ull << 0, scr_res1 = 3ull << 4, scr_rw = 1ull << 10;
	cpu.reg(scr_el3, scr_ns | scr_res1 | scr_rw);

	// HCR_EL2.RW (bit 31): EL1 is AArch64 when EL2 is implemented too.
	cpu.reg(hcr_el2, 1ull << 31);

	constexpr std::uint64_t pstate_el1h = 0x5;
	constexpr std::uint64_t pstate_daif = 0xFull << 6;
	cpu.reg(pstate, pstate_el1h | pstate_daif);

	// CPACR_EL1.FPEN[21:20] = 0b11: do not trap FP/SIMD at EL0 or EL1. The
	// compiler emits SIMD for plain struct copies, so this is not optional.
	auto cpacr = cpu.reg(cpacr_el1);
	cpacr |= (0b11ull << 20);
	cpu.reg(cpacr_el1, cpacr);
}

cpu_exception arch::intr_to_excp(const int vector) const
{
	// Unicorn hands us QEMU's exception index (target/arm/cpu.h) rather than a
	// vector number, because it calls the interrupt hook in place of
	// arm_cpu_do_interrupt.
	switch (vector)
	{
	case 1:  return cpu_exception::illegal_instruction; // EXCP_UDEF
	case 3:  return cpu_exception::page_fault;          // EXCP_PREFETCH_ABORT
	case 4:  return cpu_exception::page_fault;          // EXCP_DATA_ABORT
	case 7:  return cpu_exception::breakpoint;          // EXCP_BKPT
	default: return cpu_exception::other;
	}
}

addr_t arch::fault_addr(vcpu& cpu) const
{
	// Only meaningful if something wrote FAR_EL1. Unicorn calls the interrupt
	// hook instead of arm_cpu_do_interrupt, and it is do_interrupt that would
	// latch env->exception.vaddress into FAR_EL1, so on a translation fault
	// this reads stale state. It does not affect exception dispatch -- the
	// only consumer is win_exception::handle_page_fault, which resolves lazily
	// committed user pages, and that path needs a Unicorn-side fix (or
	// instruction decode) before it can work on this target.
	return cpu.reg(far_el1);
}

}
