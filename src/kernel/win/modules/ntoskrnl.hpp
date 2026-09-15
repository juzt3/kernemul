#pragma once

struct win_kernel_state;
struct proc_module;

namespace modules
{
	// Every handler ntoskrnl's exports are redirected to, one module per area of the kernel.
	void register_ntoskrnl(win_kernel_state& state, proc_module& mod);
}
