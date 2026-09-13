#pragma once
#include "win_kernel.hpp"
#include "../../emu/arm64/arch.hpp"

// CONTEXT_*, the architecture bit that tags an AArch64 CONTEXT and the halves a
// caller asks for on top of it.
inline constexpr std::uint32_t context_arm64   = 0x00400000;
inline constexpr std::uint32_t context_control = context_arm64 | 0x1;
inline constexpr std::uint32_t context_integer = context_arm64 | 0x2;

// Windows on ARM64. There is no GDT, no TSS and no IDT: the TEB lives in
// TPIDR_EL0, the KPCR in TPIDR_EL1, and the exception vectors are found through
// VBAR_EL1 rather than a descriptor table.
class arm64_win_emulator : public windows_emulator
{
public:
	using windows_emulator::windows_emulator;

	std::shared_ptr<vcpu> add_vcpu() override;

	void set_pcr(vcpu& cpu, const addr_t kpcr_va) override
	{
		cpu.reg(arm64::tpidr_el1, kpcr_va);
	}

	void init_thread_teb(thread& t, vcpu& cpu, addr_t teb_addr) override
	{
		t.set_reg(cpu, arm64::tpidr_el0, teb_addr);
	}

	// The integer and control halves of a CONTEXT. The Neon half is not filled
	// in: nothing asking for a thread's context here has wanted it, and what is
	// left out is left out of ContextFlags too. X29 and X30 are the frame
	// pointer and the link register, which is why the control half rather than
	// the integer one carries them.
	void capture_context(const reg_view& regs, emu_object<_CONTEXT> out,
		const std::uint32_t flags) override
	{
		if (!out)
			return;

		auto ctx = out.read();
		std::uint32_t filled = context_arm64;

		if (flags & context_integer)
		{
			filled |= context_integer;

			for (int i = 0; i <= 28; ++i)
				ctx.X[i] = regs.get(arm64::x0 + i);
		}

		if (flags & context_control)
		{
			filled |= context_control;

			ctx.Fp = regs.get(arm64::x29);
			ctx.Lr = regs.get(arm64::lr);
			ctx.Sp = regs.get(arm64::sp);
			ctx.Pc = regs.get(arm64::pc);
			ctx.Cpsr = static_cast<unsigned long>(regs.get(arm64::pstate));
		}

		ctx.ContextFlags = filled;
		out.write(ctx);
	}

	void apply_context(const reg_view& regs, emu_object<_CONTEXT> in) override
	{
		if (!in)
			return;

		const auto ctx = in.read();

		if (ctx.ContextFlags & context_integer)
		{
			for (int i = 0; i <= 28; ++i)
				regs.set(arm64::x0 + i, ctx.X[i]);
		}

		if (ctx.ContextFlags & context_control)
		{
			regs.set(arm64::x29, ctx.Fp);
			regs.set(arm64::lr, ctx.Lr);
			regs.set(arm64::sp, ctx.Sp);
			regs.set(arm64::pc, ctx.Pc);
			regs.set(arm64::pstate, ctx.Cpsr);
		}
	}
};
