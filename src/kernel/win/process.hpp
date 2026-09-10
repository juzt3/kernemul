#pragma once
#include "../process.hpp"

struct win_kernel_state;

class windows_process : public process
{
public:
	using process::process;
};

class win_user_proc : public windows_process
{
public:
	using windows_process::windows_process;
};

class win_kernel_proc : public windows_process
{
public:
	win_kernel_proc(id_type id, win_kernel_state& kernel)
		:	windows_process(id), kernel_(kernel) { }

	void module_add_cb(proc_module& mod) override;

private:
	win_kernel_state& kernel_;
};
