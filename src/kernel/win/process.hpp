#pragma once
#include "../process.hpp"
#include "win_handle_table.hpp"

struct win_kernel_state;

class windows_process : public process
{
public:
	windows_process(id_type id, std::shared_ptr<struct addr_space> space, win_obj_manager& objs)
		:	process(id, std::move(space)), objs_(objs), handle_table_(objs) {}

	std::shared_ptr<thread> create_thread(vcpu& cpu, addr_t start_addr) override;

	win_handle_table& handle_table() { return handle_table_; }

private:
	win_obj_manager& objs_;
	win_handle_table handle_table_;
};

class win_user_proc : public windows_process
{
public:
	using windows_process::windows_process;
};

class win_kernel_proc : public windows_process
{
public:
	win_kernel_proc(id_type id, win_kernel_state& kernel, std::shared_ptr<struct addr_space> space);

	void module_add_cb(proc_module& mod) override;

private:
	win_kernel_state& kernel_;
};
