#include "exception.hpp"
#include "win_kernel.hpp"
#include "unwind/unwind.hpp"
#include "../process.hpp"
#include "../../sym/symbol.hpp"
#include "../../emu/emu.hpp"
#include "../../util/log.hpp"

namespace win {

std::uint32_t exception_to_status(const cpu_exception ex)
{
	switch (ex)
	{
	case cpu_exception::divide_by_zero:      return status_integer_divide_by_zero;
	case cpu_exception::debug:               return status_single_step;
	case cpu_exception::breakpoint:          return status_breakpoint;
	case cpu_exception::illegal_instruction: return status_illegal_instruction;
	default:                                 return status_access_violation;
	}
}

win_exception::win_exception(win_kernel_state& kernel)
	: kernel_(kernel) { }

bool win_exception::handle_page_fault(vcpu& cpu)
{
	const auto t = cpu.thread();

	if (!t)
		return false;

	auto* const proc = dynamic_cast<win_user_proc*>(t->proc().get());

	if (!proc)
		return false;

	// guard pages and lazily committed pages are resolved here, everything else
	// falls through and gets dispatched as an access violation
	return proc->mem().handle_fault(cpu.arch()->fault_addr(cpu));
}

bool win_exception::handle(vcpu& cpu, const cpu_exception ex)
{
	if (ex == cpu_exception::page_fault && handle_page_fault(cpu))
		return true;

	auto& proc = *kernel_.sys_proc;
	const auto original_pc = cpu.pc();
	const auto code = exception_to_status(ex);

	LOG_INFO("exception dispatch: code=0x{:X}, rip={}", code, symbols::format_addr(proc, original_pc));

	auto mod = proc.find_module_by_addr(original_pc);
	if (!mod)
	{
		LOG_WARN("exception at 0x{:X}: not in any module", original_pc);
		return false;
	}

	std::call_once(unwinder_once_, [&] { unwinder_ = make_unwinder(*mod); });

	if (!unwinder_)
		return false;

	auto& space = *cpu.curr_addr_space();
	const auto saved_pc = cpu.pc();
	const auto saved_sp = cpu.sp();

	exception_info info{};
	info.code = code;
	info.exception_address = original_pc;

	auto uw_ctx = unwinder_->context_from_vcpu(cpu);

	for (std::size_t depth = 0; depth < 64; ++depth)
	{
		// Only the faulting frame's pc is an instruction address. Every frame
		// above it holds a return address, which points at the instruction
		// *after* the call -- outside the try scope that was active, and
		// potentially past the end of the function entirely. Step back into the
		// call before looking up the function or its scopes.
		if (depth > 0)
			uw_ctx.pc -= 1;

		mod = proc.find_module_by_addr(uw_ctx.pc);
		if (!mod)
			break;

		const auto control_pc = uw_ctx.pc;

		unwind_result result{};
		if (!unwinder_->unwind_frame(space, *mod, uw_ctx, result))
		{
			LOG_WARN("  frame[{}]: unwind failed at 0x{:X}", depth, control_pc);
			break;
		}

		LOG_INFO("  frame[{}]: rip={}, handler=0x{:X}, ret=0x{:X}",
			depth, symbols::format_addr(proc, control_pc),
			result.handler, uw_ctx.pc);

		if (!result.handler)
			continue;

		const auto hr = unwinder_->evaluate_handler(cpu, *mod, result, control_pc, info);

		if (hr.disposition == exception_execute_handler)
		{
			LOG_INFO("exception handled at frame {} -> 0x{:X}", depth, hr.target_ip);
			cpu.set_pc(hr.target_ip);
			cpu.set_sp(hr.establisher_frame);
			return true;
		}

		if (hr.disposition == exception_continue_execution)
		{
			LOG_INFO("exception continue execution at 0x{:X}", original_pc);
			cpu.set_pc(original_pc);
			cpu.set_sp(saved_sp);
			return true;
		}

		cpu.set_pc(saved_pc);
		cpu.set_sp(saved_sp);
	}

	LOG_ERR("unhandled exception code=0x{:X} at 0x{:X}", code, original_pc);
	cpu.stop();
	return false;
}

} // namespace win
