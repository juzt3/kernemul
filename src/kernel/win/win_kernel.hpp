#pragma once
#include "../kernel.hpp"
#include "../map.hpp"
#include "process.hpp"
#include "defs.hpp"

struct win_kernel_state : kernel_state
{
	static constexpr process::id_type sys_proc_id = 4;
	static constexpr process::id_type proc_id_step = 4;

	std::shared_ptr<win_kernel_proc> sys_proc;
	loaded_module_list_t loaded_module_list;

	explicit win_kernel_state(const std::shared_ptr<class emu>& emu)
		:	sys_proc(std::make_shared<win_kernel_proc>(sys_proc_id, *this, emu->default_addr_space()))
	{
		emu_ = emu;
		processes[sys_proc_id] = sys_proc;
		auto& space = *emu->default_addr_space();
		const auto head_addr = space.alloc(sizeof(list_entry), prot_rw);
		loaded_module_list = loaded_module_list_t(space, head_addr);
		loaded_module_list.init();

		krnl::map_img(*sys_proc, "fs/ntoskrnl.exe", true);
	}

	std::shared_ptr<process> create_process(const std::string_view name) override
	{
		std::scoped_lock lock(proc_mtx_);
		const auto id = next_id_;
		auto proc = std::make_shared<win_user_proc>(id, emu_->mem()->create_addr_space());
		processes[id] = proc;
		next_id_ += proc_id_step;
		return proc;
	}

private:
	std::shared_ptr<class emu> emu_;
	process::id_type next_id_ = 8;
};

class windows_emulator : public os_emulator
{
public:
	explicit windows_emulator(std::shared_ptr<class emu> emu)
		: os_emulator(std::move(emu)), kernel_(emu_)
	{ }

	win_kernel_state& kernel() { return kernel_; }

private:
	win_kernel_state kernel_;
};
