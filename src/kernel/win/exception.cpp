#include "exception.hpp"
#include "win_kernel.hpp"
#include "unwind/unwind.hpp"
#include "unwind/x64_unwind.hpp"
#include "../process.hpp"
#include "../../util/log.hpp"

namespace win {

win_exception::win_exception(win_kernel_state& kernel)
	: kernel_(kernel) { }

bool win_exception::handle(vcpu& cpu, cpu_exception ex)
{
	auto& proc = *kernel_.sys_proc;
	const auto pc = cpu.pc();

	const auto mod = proc.find_module_by_addr(pc);
	if (!mod)
		return false;

	auto unwinder = make_unwinder(*mod);
	if (!unwinder)
		return false;

	auto ctx = unwinder->context_from_vcpu(cpu);
	auto frames = walk_stack(*unwinder, *cpu.curr_addr_space(), proc, ctx);

	LOG_INFO("exception at 0x{:X}:", pc);
	for (const auto& frame : frames)
	{
		if (const auto fmod = proc.find_module_by_addr(frame.pc))
			LOG_INFO("  0x{:X} ({}+0x{:X})", frame.pc, fmod->name, frame.pc - fmod->addr);
		else
			LOG_INFO("  0x{:X}", frame.pc);
	}

	return false;
}

} // namespace win
