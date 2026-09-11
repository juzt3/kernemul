#pragma once
#include "../process.hpp"
#include "win_handle_table.hpp"
#include "peb.hpp"

struct win_kernel_state;

class windows_process : public process
{
public:
	windows_process(id_type id, std::shared_ptr<struct addr_space> space, win_obj_manager& objs)
		:	process(id, std::move(space)), objs_(objs), handle_table_(objs) {}

	std::shared_ptr<thread> create_thread(vcpu& cpu, addr_t start_addr) override;

	win_handle_table& handle_table() { return handle_table_; }

	const emu_object<_PEB64>& peb() const { return peb_; }

protected:
	win_obj_manager& objs_;
	win_handle_table handle_table_;
	emu_object<_PEB64> peb_;
};

class win_user_proc : public windows_process
{
public:
	win_user_proc(id_type id, std::shared_ptr<struct addr_space> space, win_obj_manager& objs)
		:	windows_process(id, std::move(space), objs)
	{
		const auto addr = addr_space_->alloc(peb64_alloc_size, prot_rw);
		peb_ = emu_object<_PEB64>(*addr_space_, addr);
		peb_.write(make_default_peb());
	}
};

class win_kernel_proc : public windows_process
{
public:
	win_kernel_proc(id_type id, win_kernel_state& kernel, std::shared_ptr<struct addr_space> space);

	void module_add_cb(proc_module& mod) override;

private:
	win_kernel_state& kernel_;
};
