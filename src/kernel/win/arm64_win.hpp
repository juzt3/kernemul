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
	// MRS <Xt>, <system register>: 1101 0101 0011 o0 op1 CRn CRm op2 Rt.
	// Windows services these rather than reporting them, and compiler feature
	// detection relies on it -- ucrtbase reads CurrentEL to decide whether it
	// may read the ID registers, and dies before main if neither is answered.
	static constexpr std::uint32_t mrs_op   = 0xD5300000;
	static constexpr std::uint32_t mrs_mask = 0xFFF00000;

	bool emulate_privileged_insn(vcpu& cpu) override
	{
		const auto pc = cpu.pc();
		const auto insn = cpu.read_virt_mem<std::uint32_t>(pc);

		if ((insn & mrs_mask) != mrs_op)
			return false;

		const arm64::sys_reg_enc enc{
			.op0 = 2u + ((insn >> 19) & 1),
			.op1 = (insn >> 16) & 7,
			.crn = (insn >> 12) & 15,
			.crm = (insn >> 8) & 15,
			.op2 = (insn >> 5) & 7,
		};

		std::uint64_t value = 0;

		if (!read_sysreg(cpu, enc, value))
		{
			THREAD_LOG_WARN("MRS S{}_{}_C{}_C{}_{} at 0x{:X} is not one usermode is "
				"answered about", enc.op0, enc.op1, enc.crn, enc.crm, enc.op2, pc);
			return false;
		}

		const auto rt = insn & 31;

		// Rt 31 is the zero register on this instruction, not the stack pointer.
		if (rt != 31)
			cpu.reg(arm64::x0 + rt, value);

		cpu.set_pc(pc + 4);

		return true;
	}

	// True if usermode gets an answer. Values come from the backend's own cpu
	// rather than being invented.
	static bool read_sysreg(vcpu& cpu, const arm64::sys_reg_enc enc, std::uint64_t& out)
	{
		// CurrentEL, bits 3:2. A user thread is at EL0.
		if (enc.op0 == 3 && enc.op1 == 0 && enc.crn == 4 && enc.crm == 2 && enc.op2 == 2)
		{
			out = 0;
			return true;
		}

		for (const auto r : { arm64::id_aa64pfr0_el1, arm64::id_aa64isar0_el1,
			arm64::id_aa64isar1_el1, arm64::id_aa64mmfr0_el1 })
		{
			const auto known = arm64::sys_enc(r);

			if (known.op0 == enc.op0 && known.op1 == enc.op1 && known.crn == enc.crn
				&& known.crm == enc.crm && known.op2 == enc.op2)
			{
				out = cpu.reg(r);
				return true;
			}
		}

		return false;
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
			{
				// x18 is the platform register, not a general one. Restoring it
				// out of a CONTEXT would put a stale TEB -- or a zero, for a
				// context built by hand -- in the register every caller
				// dereferences. Windows does not restore it either: neither
				// RtlRestoreContext nor NtContinue touches x18.
				if (i == 18)
					continue;

				regs.set(arm64::x0 + i, ctx.X[i]);
			}
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

			// The flag bits come out of the context; the mode does not. A
			// CONTEXT the guest built carries whatever Cpsr ntdll left in it,
			// and a kernel thread continued through one of those would find
			// itself at EL0 -- which is the analogue of the cs check the x86-64
			// side does before it lets a context pick a ring.
			const auto mode = regs.is_user() ? pstate_el0t : pstate_el1h;
			regs.set(arm64::pstate, (ctx.Cpsr & ~pstate_mode_mask) | mode);
		}
	}
};
