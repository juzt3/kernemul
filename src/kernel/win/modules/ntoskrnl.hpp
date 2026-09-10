#pragma once

struct kernel_state;
struct proc_module;

namespace modules
{
	void register_ntoskrnl(kernel_state& state, proc_module& mod);
}
