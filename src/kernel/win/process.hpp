#pragma once
#include "../process.hpp"

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
	using windows_process::windows_process;
	void module_add_cb(proc_module& mod) override;
};
