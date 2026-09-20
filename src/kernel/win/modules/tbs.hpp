#pragma once

struct win_kernel_state;
struct proc_module;

namespace modules
{
	void register_tbs(win_kernel_state& state, proc_module& mod);
}
