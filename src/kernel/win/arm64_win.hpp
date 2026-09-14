#pragma once
#include "win_kernel.hpp"
#include "../../emu/arm64/arch.hpp"

// CONTEXT_*, the AArch64 tag and the halves asked for on top of it.
inline constexpr context_flags context_arm64   { 0x00400000 };
inline constexpr context_flags context_control = context_arm64.with(0x1);
inline constexpr context_flags context_integer = context_arm64.with(0x2);
inline constexpr context_flags context_float   = context_arm64.with(0x4);

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

	// fpcr and fpsr are registers the backend has, but not ones a thread's
	// context is saved from -- see arm64::arch::regs() -- so a banked thread
	// has no copy of them to give. These are what a thread runs with instead.
	static constexpr std::uint32_t default_fpcr = 0;
	static constexpr std::uint32_t default_fpsr = 0;

	void capture_context(const reg_view& regs, emu_object<_CONTEXT> out,
		const context_flags flags) override
	{
		if (!out)
			return;

		auto ctx = out.read();
		auto filled = context_arm64;

		if (flags.has(context_integer))
		{
			filled |= context_integer;

			for (int i = 0; i <= 28; ++i)
				ctx.X[i] = regs.get(arm64::x0 + i);
		}

		// d8-d15 are nonvolatile, and this is the only place they reach a
		// CONTEXT: a frame that spilled one and is then unwound past gets it
		// back out of here.
		if (flags.has(context_float))
		{
			filled |= context_float;

			ctx.Fpcr = default_fpcr;
			ctx.Fpsr = default_fpsr;

			for (int i = 0; i < 32; ++i)
			{
				const auto value = regs.get_reg<arm64::vec_t>(arm64::q0 + i);

				ctx.V[i].Low = value.low;
				ctx.V[i].High = static_cast<std::int64_t>(value.high);
			}
		}

		if (flags.has(context_control))
		{
			filled |= context_control;

			ctx.Fp = regs.get(arm64::x29);
			ctx.Lr = regs.get(arm64::lr);
			ctx.Sp = regs.get(arm64::sp);
			ctx.Pc = regs.get(arm64::pc);
			ctx.Cpsr = static_cast<std::uint32_t>(regs.get(arm64::pstate));
		}

		ctx.ContextFlags = filled.bits;
		out.write(ctx);
	}

	void apply_context(const reg_view& regs, emu_object<_CONTEXT> in) override
	{
		if (!in)
			return;

		const auto ctx = in.read();
		const context_flags flags{ ctx.ContextFlags };

		if (flags.has(context_integer))
		{
			for (int i = 0; i <= 28; ++i)
				regs.set(arm64::x0 + i, ctx.X[i]);
		}

		if (flags.has(context_float))
		{
			for (int i = 0; i < 32; ++i)
			{
				const auto& saved = ctx.V[i];

				regs.set_reg(arm64::q0 + i, arm64::vec_t{
					.low = saved.Low,
					.high = static_cast<std::uint64_t>(saved.High),
				});
			}
		}

		if (flags.has(context_control))
		{
			regs.set(arm64::x29, ctx.Fp);
			regs.set(arm64::lr, ctx.Lr);
			regs.set(arm64::sp, ctx.Sp);
			regs.set(arm64::pc, ctx.Pc);
			regs.set(arm64::pstate, ctx.Cpsr);
		}
	}
};
