#pragma once
#include "win_kernel.hpp"
#include "syscalls.hpp"
#include "thread.hpp"
#include "../../emu/arm64/arch.hpp"
#include <cstring>
#include <span>

inline constexpr context_flags context_arm64   { 0x00400000 };
inline constexpr context_flags context_control = context_arm64.with(0x1);
inline constexpr context_flags context_integer = context_arm64.with(0x2);
inline constexpr context_flags context_float   = context_arm64.with(0x4);

inline constexpr context_flags context_full =
	context_control | context_integer | context_float;

// The service number is the SVC immediate, so it has to come out of the trapping instruction.
struct arm64_win_syscall : win_syscall
{
	// svc #imm16: 1101'0100'000i'iiii'iiii'iiii'iii0'0001
	static constexpr std::uint32_t svc_op   = 0xD4000001;
	static constexpr std::uint32_t svc_mask = 0xFFE0001F;

	[[nodiscard]] std::uint32_t id(vcpu& cpu) const override
	{
		return decode(cpu.read_virt_mem<std::uint32_t>(cpu.pc())).value_or(0);
	}

	// The whole stub is "svc #service_number; ret"; fixed width, so the first word is it.
	[[nodiscard]] std::optional<std::uint32_t> decode_id(
		const std::span<const std::uint8_t> stub) const override
	{
		if (stub.size() < sizeof(std::uint32_t))
			return std::nullopt;

		std::uint32_t insn = 0;
		std::memcpy(&insn, stub.data(), sizeof(insn));

		return decode(insn);
	}

private:
	[[nodiscard]] static constexpr std::optional<std::uint32_t> decode(const std::uint32_t insn)
	{
		if ((insn & svc_mask) != svc_op)
			return std::nullopt;

		return (insn >> 5) & 0xFFFF;
	}
};

class arm64_win_emulator : public windows_emulator
{
public:
	using windows_emulator::windows_emulator;

	std::shared_ptr<vcpu> add_vcpu() override;

	// PSTATE.M[3:0]: EL0t is the only mode EL0 has, EL1h is EL1 on SP_EL1.
	static constexpr std::uint64_t pstate_el0t = 0x0;
	static constexpr std::uint64_t pstate_el1h = 0x5;
	static constexpr std::uint64_t pstate_mode_mask = 0xF;

	// x18 is the platform register the guest dereferences: KPCR in kernel, TEB in user mode.
	void set_pcr(vcpu& cpu, const addr_t kpcr_va) override
	{
		cpu.reg(arm64::tpidr_el1, kpcr_va);
		cpu.reg(arm64::x18, kpcr_va);
	}

	void init_thread_teb(thread& t, vcpu& cpu, addr_t teb_addr) override
	{
		t.set_reg(cpu, arm64::tpidr_el0, teb_addr);
		t.set_reg(cpu, arm64::x18, teb_addr);

		const auto pstate = t.get_reg(cpu, arm64::pstate);
		t.set_reg(cpu, arm64::pstate, (pstate & ~pstate_mode_mask) | pstate_el0t);
	}

	// LdrInitializeThunk(context, ntdll_base); the thunk keeps x0 and hands it to NtContinue.
	// The context continues into RtlUserThreadStart(entry_point, argument) -- the argument is
	// what the guest passed to NtCreateThreadEx, and zero for the thread the process starts on.
	void setup_loader_frame(thread& t, vcpu& cpu, const addr_t entry_point,
		const addr_t ntdll_base, const addr_t argument) override
	{
		const auto* const ut = dynamic_cast<const win_thread*>(&t);

		if (!ut)
			return;

		auto& space = *t.proc()->addr_space();
		const auto thread_start = t.proc()->thread_exit_addr();

		const addr_t stack_top = (ut->stack_base() - 0x1000) & ~addr_t(0xF);
		const addr_t context_addr = (stack_top - sizeof(_CONTEXT)) & ~addr_t(0xF);

		_CONTEXT ctx{};
		ctx.ContextFlags = context_full.bits;
		ctx.Cpsr = static_cast<std::uint32_t>(pstate_el0t);
		ctx.Pc = thread_start;
		ctx.Sp = stack_top;
		ctx.X[0] = entry_point;
		ctx.X[1] = argument;

		ctx.Lr = 0;
		ctx.Fp = 0;

		space.write_mem(context_addr, &ctx, sizeof(ctx));


		if (const auto& teb = ut->teb())
			teb.field(&_TEB64::IsImpersonating).write(1u);

		t.set_reg(cpu, arm64::sp, context_addr);
		t.set_reg(cpu, arm64::x0, context_addr);
		t.set_reg(cpu, arm64::x1, ntdll_base);

		LOG_INFO("user thread {}: context at 0x{:X}, stack 0x{:X}-0x{:X}, "
			"continues to 0x{:X} with entry 0x{:X}",
			t.id(), context_addr, ut->stack_limit(), ut->stack_base(),
			thread_start, entry_point);
	}

	// From the dispatcher: "add x0, sp, #0x3B0" is the record, "add x1, sp, #0" the context.
	static constexpr addr_t exception_record_offset = 0x3B0;
	static_assert(sizeof(_CONTEXT) <= exception_record_offset,
		"a CONTEXT has to fit under the record the dispatcher expects above it");

	// The dispatcher's unwind codes are MSFT_OP_CONTEXT then end, so the context sits at the sp.
	bool setup_exception_frame(vcpu& cpu, const addr_t dispatcher,
		const win::exception_info& info) override
	{
		auto& space = *cpu.curr_addr_space();

		constexpr addr_t frame =
			(exception_record_offset + sizeof(_EXCEPTION_RECORD) + 0xF) & ~addr_t(0xF);

		const addr_t context_addr = (cpu.sp() - 0x100 - frame) & ~addr_t(0xF);
		const addr_t record_addr = context_addr + exception_record_offset;

		emu_object<_CONTEXT> context(space, context_addr);
		context.write(_CONTEXT{});
		capture_context({cpu}, context, context_all);

		context.field(&_CONTEXT::ContextFlags).write(context_full.bits);

		_EXCEPTION_RECORD record{};
		record.ExceptionCode = static_cast<std::int32_t>(info.code);
		record.ExceptionAddress = reinterpret_cast<void*>(
			static_cast<std::uintptr_t>(info.exception_address));

		if (info.code == win::status_access_violation)
		{
			record.NumberParameters = 2;
			record.ExceptionInformation[1] = info.fault_address;
		}

		space.write_mem(record_addr, record);

		cpu.set_sp(context_addr);
		cpu.set_pc(dispatcher);

		return true;
	}

	// MRS <Xt>, <system register>: 1101 0101 0011 o0 op1 CRn CRm op2 Rt.
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

	static bool read_sysreg(vcpu& cpu, const arm64::sys_reg_enc enc, std::uint64_t& out)
	{
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

	// fpcr and fpsr are not part of a thread's saved context, so these are what it runs with.
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
				// Neither RtlRestoreContext nor NtContinue restores x18 out of a CONTEXT.
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

			// The flag bits come out of the context; the mode does not.
			const auto mode = regs.is_user() ? pstate_el0t : pstate_el1h;
			regs.set(arm64::pstate, (ctx.Cpsr & ~pstate_mode_mask) | mode);
		}
	}
};
