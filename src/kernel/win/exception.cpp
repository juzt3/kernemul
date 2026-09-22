#include "exception.hpp"
#include "win_kernel.hpp"
#include "thread.hpp"
#include "unwind/unwind.hpp"
#include "../process.hpp"
#include "../../sym/symbol.hpp"
#include "../../emu/emu.hpp"
#include "../../util/log.hpp"

namespace win
{

namespace
{

// A /GS function names the compiler's own __GSHandlerCheck as its personality routine. It
// validates the stack cookie the prologue stored on the frame and then continues the search.
// The cookie is one the emulator may have rebuilt rather than had the prologue write -- an
// obfuscated function can be entered past its prologue -- so the check can only ever fail here,
// and failing it bugchecks the guest. Skipping it is what a passing check would have done.
bool is_gs_handler(addr_space& space, const addr_t handler)
{
	static constexpr std::uint8_t gs_stub[] = {
		0x48, 0x83, 0xEC, 0x28, 0x4D, 0x8B, 0x41, 0x38,
		0x48, 0x8B, 0xCA, 0x49, 0x8B, 0xD1, 0xE8,
	};

	if (!handler)
		return false;

	for (std::size_t i = 0; i < sizeof(gs_stub); ++i)
	{
		if (space.read_mem<std::uint8_t>(handler + i) != gs_stub[i])
			return false;
	}

	return true;
}

}


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

	return proc->mem().handle_fault(cpu.arch()->fault_addr(cpu));
}

bool win_exception::handle(vcpu& cpu, const cpu_exception ex)
{
	if (ex == cpu_exception::page_fault && handle_page_fault(cpu))
		return true;

	// Some of what usermode may not execute is serviced rather than reported.
	if (ex == cpu_exception::illegal_instruction)
	{
		auto* const emulator = kernel_.emulator();

		if (emulator && emulator->emulate_privileged_insn(cpu))
			return true;
	}

	const auto t = cpu.thread();
	const auto faulting = t ? std::dynamic_pointer_cast<windows_process>(t->proc()) : nullptr;
	auto& proc = faulting ? *faulting : *kernel_.sys_proc;

	const auto original_pc = cpu.pc();
	const auto code = exception_to_status(ex);

	cpu.arch()->on_exception(cpu);

	LOG_INFO("exception dispatch: code=0x{:X}, rip={}, address=0x{:X}", code,
		symbols::format_addr(proc, original_pc), cpu.arch()->fault_addr(cpu));

	exception_info info{};
	info.code = code;
	info.exception_address = original_pc;
	info.fault_address = cpu.arch()->fault_addr(cpu);

	// There is no loader under a driver to own a dispatcher, so the walk below stays here.
	if (dynamic_cast<win_user_proc*>(&proc))
	{
		std::optional<addr_t> dispatcher;

		if (const auto ntdll = proc.find_module(ntdll_name))
			dispatcher = ntdll->find_symbol(user_exception_dispatcher);

		auto* const emulator = kernel_.emulator();

		if (!dispatcher || !emulator)
		{
			LOG_ERR("{}!{} is not available, so a user fault cannot be delivered",
				ntdll_name, user_exception_dispatcher);

			return false;
		}

		if (!emulator->setup_exception_frame(cpu, *dispatcher, info))
		{
			LOG_ERR("this architecture cannot build an exception frame yet");
			return false;
		}

		LOG_INFO("  delivered to {}!{} at 0x{:X}", ntdll_name,
			user_exception_dispatcher, *dispatcher);

		return true;
	}

	auto mod = proc.find_module_by_addr(original_pc);
	if (!mod)
	{
		LOG_ERR("exception at 0x{:X}: not in any module this process knows of", original_pc);
		return false;
	}

	std::call_once(unwinder_once_, [&] { unwinder_ = make_unwinder(*mod); });

	if (!unwinder_)
		return false;

	auto& space = *cpu.curr_addr_space();
	const auto saved_pc = cpu.pc();
	const auto saved_sp = cpu.sp();

	auto uw_ctx = unwinder_->context_from_vcpu(cpu);

	for (std::size_t depth = 0; depth < 64; ++depth)
	{
		// Every frame above the faulting one holds a return address, so step back into the call.
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

		// A /GS function's handler only validates the stack cookie the prologue saved and then passes
		// the search on, so this is that check: the stored value at the frame displacement the
		// unwind data carries is compared with the cookie the image's load config says is in
		// use. On a real machine the handler is entered to make the same comparison.
		if (is_gs_handler(space, result.handler))
		{
			bool passed = false;

			if (const auto* const pe = mod->pe())
			{
				if (const auto* const lc = pe->load_config(); lc && lc->security_cookie)
				{
					const auto cookie_addr =
						mod->addr + (lc->security_cookie - pe->base_addr());
					const auto expected = space.read_mem<std::uint64_t>(cookie_addr);

					if (result.handler_data)
					{
						const auto data = space.read_mem<std::uint32_t>(result.handler_data);

						// Encoded as a frame displacement: a set low bit means the cookie sits
						// above the frame, otherwise below it.
						const addr_t candidates[] = {
							result.establisher_frame - data,
							result.establisher_frame + (data & ~1u),
						};

						for (const auto gs : candidates)
						{
							if (gs && space.read_mem<std::uint64_t>(gs) == expected)
							{
								passed = true;
								break;
							}
						}
					}
				}
			}

			if (passed)
			{
				LOG_INFO("  frame[{}]: GS check passed at 0x{:X}", depth, result.handler);
			}
			else
			{
				LOG_ERR("  frame[{}]: GS cookie mismatch at 0x{:X}; the walk moves on, where a "
					"real machine would fault on the check", depth, result.handler);
			}

			continue;
		}

		auto* emulator = kernel_.emulator();

		if (!emulator)
			break;

		// The frame names its own personality routine, so ask it rather than assume.
		const auto frame = build_dispatch_frame(cpu, *emulator, info);

		dispatcher_context64 dispatch{};
		dispatch.control_pc = control_pc;
		dispatch.image_base = mod->addr;
		dispatch.function_entry = result.function_entry;
		dispatch.establisher_frame = result.establisher_frame;
		dispatch.context_record = frame.context;
		dispatch.language_handler = result.handler;
		dispatch.handler_data = result.handler_data;

		space.write_mem(frame.dispatcher, dispatch);

		const std::uint64_t args[] = {
			frame.record, result.establisher_frame, frame.context, frame.dispatcher };

		LOG_INFO("  calling handler at 0x{:X} (handler_data=0x{:X}, scopes={}, frame=0x{:X})",
			result.handler, result.handler_data,
			result.handler_data ? space.read_mem<std::uint32_t>(result.handler_data) : 0,
			result.establisher_frame);

		const auto disposition = static_cast<std::int32_t>(
			kernel_.calls.call(cpu, result.handler, args, frame.scratch));

		const auto answered = space.read_mem<dispatcher_context64>(frame.dispatcher);

		LOG_INFO("  handler returned {} (target=0x{:X})", disposition, answered.target_ip);

		if (disposition == exception_execute_handler && answered.target_ip)
		{
			LOG_INFO("exception handled at frame {} -> 0x{:X}", depth, answered.target_ip);
			cpu.set_pc(answered.target_ip);
			cpu.set_sp(answered.establisher_frame);
			return true;
		}

		if (disposition == exception_continue_execution)
		{
			LOG_INFO("exception continue execution at 0x{:X}", original_pc);
			cpu.set_pc(original_pc);
			cpu.set_sp(saved_sp);
			return true;
		}

		cpu.set_pc(saved_pc);
		cpu.set_sp(saved_sp);
	}

	// A trap-flag step no frame claimed. On a real machine with no debugger attached a user-mode
	// single step is a second-chance exception the process does not survive, while a kernel-mode
	// one is the kernel stepping its own code and is taken and resumed. Clearing and resuming a
	// user step is what leaves a probe alive that a real machine would have ended.
	if (ex == cpu_exception::debug)
	{
		const bool user = dynamic_cast<win_user_proc*>(&proc) != nullptr;
		const auto win_t = t ? std::dynamic_pointer_cast<win_thread>(t) : nullptr;

		if (user && win_t)
		{
			LOG_WARN("debug trap at 0x{:X} unclaimed: thread {} ends with STATUS_SINGLE_STEP",
				original_pc, win_t->id());

			win_t->set_exit_status(status_single_step);
			win_t->finish();
			cpu.stop();

			return true;
		}

		LOG_INFO("debug trap at 0x{:X} unclaimed in kernel mode: cleared and resumed", original_pc);
		return true;
	}

	LOG_ERR("unhandled exception code=0x{:X} at 0x{:X}", code, original_pc);
	return false;
}

} // namespace win
