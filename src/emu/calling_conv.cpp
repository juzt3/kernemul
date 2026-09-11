#include "calling_conv.hpp"
#include "../kernel/thread_scheduler.hpp"

void x86_win_conv::set_arg(vcpu& cpu, thread& t, const std::size_t index, const std::uint64_t value) const
{
	static constexpr reg_t regs[] = { x86::rcx, x86::rdx, x86::r8, x86::r9 };

	if (index < 4)
		t.set_reg(cpu, regs[index], value);
}
