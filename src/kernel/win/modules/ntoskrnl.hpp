#pragma once

struct win_kernel_state;
struct proc_module;

namespace modules
{
	// Every handler ntoskrnl's exports are redirected to, in the order the
	// areas were added. One module per area of the kernel, and this is the list
	// of them.
	void register_ntoskrnl(win_kernel_state& state, proc_module& mod);
}
