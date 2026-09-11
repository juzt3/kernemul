#include "exception.hpp"
#include "win_kernel.hpp"
#include "unwind/unwind.hpp"
#include "unwind/x64_unwind.hpp"
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

static bool try_dispatch_handler(
	const proc_module& mod, const addr_t control_pc,
	const unwind_result& unwind, vcpu& cpu)
{
	if (!unwind.handler || !unwind.handler_data)
		return false;

	const auto* img = mod.pe();
	if (!img)
		return false;

	const auto* img_base = img->as<const std::uint8_t*>();
	const auto handler_data_rva = static_cast<std::uint32_t>(unwind.handler_data - mod.addr);
	const auto* scope_table_ptr = reinterpret_cast<const std::uint32_t*>(img_base + handler_data_rva);
	const auto scope_count = scope_table_ptr[0];
	const auto* scopes = reinterpret_cast<const scope_entry*>(&scope_table_ptr[1]);

	const auto control_pc_rva = static_cast<std::uint32_t>(control_pc - mod.addr);

	for (std::uint32_t i = 0; i < scope_count; ++i)
	{
		const auto& scope = scopes[i];

		if (control_pc_rva < scope.begin_address || control_pc_rva >= scope.end_address)
			continue;

		if (!scope.jump_target)
			continue;

		if (scope.handler_address == 1)
		{
			const auto target = mod.addr + scope.jump_target;
			LOG_INFO("  EXCEPTION_EXECUTE_HANDLER, jumping to 0x{:X}", target);

			cpu.set_pc(target);
			cpu.set_sp(unwind.establisher_frame);
			return true;
		}

		// TODO: evaluate filter expression via nested emulation
		LOG_WARN("  scope[{}] has filter at rva 0x{:X}, skipping (not yet supported)",
			i, scope.handler_address);
	}

	return false;
}

win_exception::win_exception(win_kernel_state& kernel)
	: kernel_(kernel) { }

bool win_exception::handle(vcpu& cpu, const cpu_exception ex)
{
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

	if (!unwinder_)
	{
		unwinder_ = make_unwinder(*mod);
		if (!unwinder_)
			return false;
	}

	auto ctx = unwinder_->context_from_vcpu(cpu);

	constexpr std::size_t max_frames = 64;

	for (std::size_t depth = 0; depth < max_frames; ++depth)
	{
		mod = proc.find_module_by_addr(ctx.pc);
		if (!mod)
			break;

		const auto control_pc = ctx.pc;
		const auto control_rva = static_cast<std::uint32_t>(control_pc - mod->addr);

		unwind_result result{};
		if (!unwinder_->unwind_frame(*cpu.curr_addr_space(), *mod, ctx, result))
		{
			LOG_WARN("  frame[{}]: unwind failed at rva 0x{:X}", depth, control_rva);
			break;
		}

		LOG_INFO("  frame[{}]: rip={}, handler=0x{:X}, ret=0x{:X}",
			depth, symbols::format_addr(proc, control_pc),
			result.handler, ctx.pc);

		if (result.handler)
		{
			if (try_dispatch_handler(*mod, control_pc, result, cpu))
			{
				LOG_INFO("exception handled at frame {}", depth);
				return true;
			}
		}
	}

	LOG_ERR("unhandled exception code=0x{:X} at 0x{:X}", code, original_pc);
	cpu.stop();
	return false;
}

} // namespace win
