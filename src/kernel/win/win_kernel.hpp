#pragma once
#include "../kernel.hpp"
#include "process.hpp"
#include "defs.hpp"

struct win_kernel_state : kernel_state
{
	static constexpr process::id_type sys_proc_id = 4;
	static constexpr process::id_type proc_id_step = 4;

	std::shared_ptr<win_kernel_proc> sys_proc;
	loaded_module_list_t loaded_module_list;

	win_kernel_state()
		:	sys_proc(std::make_shared<win_kernel_proc>(sys_proc_id, *this))
	{
		processes[sys_proc_id] = sys_proc;
	}

	void init(addr_space& space_)
	{
		const auto head_addr = space_.alloc(sizeof(list_entry), prot_rw);
		loaded_module_list = loaded_module_list_t(space_, head_addr);
		loaded_module_list.init();
	}

	std::shared_ptr<process> create_process(const std::string_view name) override
	{
		std::scoped_lock lock(proc_mtx_);
		const auto id = next_id_;
		auto proc = std::make_shared<win_user_proc>(id);
		processes[id] = proc;
		next_id_ += proc_id_step;
		return proc;
	}

private:
	process::id_type next_id_ = 8;
};

class windows_emulator : public os_emulator
{
public:
	using os_emulator::os_emulator;

	win_kernel_state& kernel() { return kernel_; }

private:
	win_kernel_state kernel_;
};
