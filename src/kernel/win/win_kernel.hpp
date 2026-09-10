#pragma once
#include "../kernel.hpp"
#include "../map.hpp"
#include "process.hpp"
#include "defs.hpp"
#include <cstring>

struct win_kernel_state : kernel_state
{
	static constexpr process::id_type sys_proc_id = 4;
	static constexpr process::id_type proc_id_step = 4;

	std::shared_ptr<win_kernel_proc> sys_proc;
	loaded_module_list_t loaded_module_list;
	active_process_list_t active_process_list;

	explicit win_kernel_state(const std::shared_ptr<class emu>& emu)
		:	sys_proc(std::make_shared<win_kernel_proc>(sys_proc_id, *this, emu->default_addr_space()))
	{
		emu_ = emu;
		processes[sys_proc_id] = sys_proc;
		auto& space = *emu->default_addr_space();

		if (const auto ntoskrnl = krnl::map_img(*sys_proc, "fs/ntoskrnl.exe", true))
		{
			if (const auto ps_list = ntoskrnl->find_export("PsLoadedModuleList"))
			{
				loaded_module_list = loaded_module_list_t(space, *ps_list);
				loaded_module_list.init();
				sys_proc->module_add_cb(*ntoskrnl);
			}

			if (const auto ps_active = ntoskrnl->find_export("PsActiveProcessHead"))
			{
				active_process_list = active_process_list_t(space, *ps_active);
				active_process_list.init();
			}

			if (const auto ps_init = ntoskrnl->find_export("PsInitialSystemProcess"))
			{
				auto sys_eproc = insert_process(space, sys_proc_id, "System");
				space.write_mem(*ps_init, sys_eproc.address());
			}
		}
	}

	std::shared_ptr<process> create_process(const std::string_view name) override
	{
		std::scoped_lock lock(proc_mtx_);
		const auto id = next_id_;
		auto proc = std::make_shared<win_user_proc>(id, emu_->mem()->create_addr_space());
		processes[id] = proc;
		next_id_ += proc_id_step;

		if (active_process_list.address())
			insert_process(*emu_->default_addr_space(), id, name);

		return proc;
	}

private:
	emu_object<_EPROCESS> insert_process(addr_space& space, process::id_type id, std::string_view name)
	{
		_EPROCESS ep{};
		ep.UniqueProcessId = reinterpret_cast<void*>(static_cast<std::uintptr_t>(id));
		std::memcpy(ep.ImageFileName, name.data(), std::min(name.size(), sizeof(ep.ImageFileName)));
		return active_process_list.push_back(ep);
	}

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
