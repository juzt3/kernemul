#pragma once
#include "../kernel.hpp"
#include "process.hpp"
#include "exception.hpp"
#include "defs.hpp"
#include "modules/ntoskrnl.hpp"
#include "modules/nt_thread_ops.hpp"
#include "modules/nt_object_ops.hpp"
#include <cstring>

struct win_kernel_state : kernel_state
{
	win_obj_manager objs;
	std::shared_ptr<win_kernel_proc> sys_proc;
	loaded_module_list_t loaded_module_list;
	active_process_list_t active_process_list;

	explicit win_kernel_state(const std::shared_ptr<class emu>& emu)
		:	objs(*emu->default_addr_space()),
			sys_proc(std::make_shared<win_kernel_proc>(objs.allocate_id(), *this, emu->default_addr_space()))
	{
		emu_ = emu;
		processes[sys_proc->id()] = sys_proc;
		auto& space = *emu->default_addr_space();

		if (const auto ntoskrnl = map_redirect_module(*sys_proc, "fs/ntoskrnl.exe", true))
		{
			modules::register_ntoskrnl(*this, *ntoskrnl);
			modules::register_ntoskrnl_thread_ops(*this, *ntoskrnl);
			modules::register_ntoskrnl_object_ops(*this, *ntoskrnl);

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
				auto sys_eproc = insert_process(space, sys_proc->id(), "System");
				space.write_mem(*ps_init, sys_eproc.address());
			}
		}
	}

	std::shared_ptr<process> create_process(const std::string_view name) override
	{
		std::scoped_lock lock(proc_mtx_);
		const auto id = objs.allocate_id();
		auto proc = std::make_shared<win_user_proc>(id, emu_->mem()->create_addr_space(), objs);
		processes[id] = proc;

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

};

class windows_emulator : public os_emulator
{
public:
	explicit windows_emulator(std::shared_ptr<class emu> emu)
		: os_emulator(std::move(emu)), kernel_(emu_)
	{
		kernel_.sys_proc->set_scheduler(&scheduler_);
		excp_ = std::make_shared<win::win_exception>(kernel_);
	}

	win_kernel_state& kernel() { return kernel_; }

	std::shared_ptr<thread> create_kernel_thread(vcpu& cpu, const addr_t start_addr) override
	{
		return kernel_.sys_proc->create_thread(cpu, start_addr);
	}

private:
	win_kernel_state kernel_;
};
