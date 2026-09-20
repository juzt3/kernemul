#pragma once

struct win_kernel_state;
struct proc_module;

namespace modules
{
	void register_ntoskrnl_iocp_ops(win_kernel_state& state, proc_module& mod);
}
