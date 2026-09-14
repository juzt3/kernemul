#pragma once
#include "arch.hpp"
#include "calling_conv.hpp"
#include "emu.hpp"
#include <cstdint>
#include <mutex>
#include <span>
#include <vector>

// Hands the rest of the call to `routine`: the return address is left alone, so
// it returns straight to whoever called the export, with its own result.
inline void guest_tail_call(vcpu& cpu, const addr_t routine,
	const std::span<const std::uint64_t> args)
{
	const auto& conv = *cpu.emu()->call_conv();

	for (std::size_t i = 0; i < args.size(); ++i)
		conv.write_arg(cpu, i, args[i]);

	cpu.set_pc(routine);
}

// Runs a guest routine and comes back with what it returned. The quantum timer
// cannot take a nested run away (see vcpu::try_stop), so this is only for the
// routines the guest hands over expecting them back.
class guest_caller
{
public:
	// `scratch` bytes above the routine's frame survive the call; scratch_base
	// says where they are.
	std::uint64_t call(vcpu& cpu, addr_t routine, std::span<const std::uint64_t> args,
		std::size_t scratch = 0)
	{
		const auto a = cpu.arch();
		const auto regs = a->regs();
		const auto& conv = *cpu.emu()->call_conv();

		std::vector<reg_val> saved(regs.size());

		for (std::size_t i = 0; i < regs.size(); ++i)
			cpu.reg_read(regs[i], &saved[i], a->reg_size(regs[i]));

		cpu.set_sp(scratch_base(cpu, scratch));
		a->set_ret_addr(cpu, trampoline(cpu));

		for (std::size_t i = 0; i < args.size(); ++i)
			conv.write_arg(cpu, i, args[i]);

		cpu.set_pc(routine);
		cpu.run();

		const auto result = conv.read_ret(cpu);

		for (std::size_t i = 0; i < regs.size(); ++i)
			cpu.reg_write(regs[i], &saved[i], a->reg_size(regs[i]));

		return result;
	}

	static addr_t scratch_base(vcpu& cpu, const std::size_t size)
	{
		return (cpu.sp() - red_zone - size) & ~addr_t(0xF);
	}

private:
	// Clear of the handler's frame, so a routine reading past its arguments --
	// x64 home space, a varargs spill -- stays off it.
	static constexpr addr_t red_zone = 0x100;

	// Returned to rather than executed: the hook fires on the address.
	addr_t trampoline(vcpu& cpu)
	{
		std::call_once(once_, [&]
		{
			trampoline_ = cpu.curr_addr_space()->alloc(0x1000, prot_rwx);

			cpu.emu()->hook_code(trampoline_, trampoline_,
				[](vcpu& c, addr_t, std::size_t) { c.stop(); });
		});

		return trampoline_;
	}

	std::once_flag once_;
	addr_t trampoline_ = 0;
};
