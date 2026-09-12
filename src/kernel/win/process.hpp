#pragma once
#include "../process.hpp"
#include "win_handle_table.hpp"
#include "eb.hpp"
#include "ldr.hpp"

struct win_kernel_state;
class windows_emulator;

class windows_process : public process
{
public:
	windows_process(id_type id, std::shared_ptr<struct addr_space> space, win_obj_manager& objs)
		:	process(id, std::move(space)), objs_(objs), handle_table_(objs) {}

	std::shared_ptr<thread> create_thread(vcpu& cpu, addr_t start_addr) override;

	win_handle_table& handle_table() { return handle_table_; }

	const emu_object<_PEB64>& peb() const { return peb_; }

	void set_emulator(windows_emulator* e) { emulator_ = e; }

protected:
	win_obj_manager& objs_;
	win_handle_table handle_table_;
	emu_object<_PEB64> peb_;
	windows_emulator* emulator_ = nullptr;
};

class win_user_proc : public windows_process
{
public:
	win_user_proc(id_type id, std::shared_ptr<struct addr_space> space, win_obj_manager& objs)
		:	windows_process(id, std::move(space), objs)
	{
		auto& sp = *addr_space_;

		const auto peb_addr = sp.alloc(peb64_alloc_size, prot_rw);
		peb_ = emu_object<_PEB64>(sp, peb_addr);
		peb_.write(make_default_peb());

		const auto ldr_addr = sp.alloc(peb_ldr_data64_alloc_size, prot_rw);
		ldr_ = ldr_module_list(sp, ldr_addr);

		auto peb = peb_.read();
		peb.Ldr = ldr_addr;
		peb_.write(peb);
	}

	void module_add_cb(proc_module& mod) override;

	std::shared_ptr<thread> create_thread(vcpu& cpu, addr_t start_addr) override;

private:
	ldr_module_list ldr_;
};

class win_kernel_proc : public windows_process
{
public:
	win_kernel_proc(id_type id, win_kernel_state& kernel, std::shared_ptr<struct addr_space> space);

	void module_add_cb(proc_module& mod) override;

private:
	win_kernel_state& kernel_;
};
