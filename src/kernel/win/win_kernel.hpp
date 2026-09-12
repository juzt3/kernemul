#pragma once
#include "../kernel.hpp"
#include "process.hpp"
#include "exception.hpp"
#include "defs.hpp"
#include "modules/ntoskrnl.hpp"
#include "modules/nt_thread_ops.hpp"
#include "modules/nt_object_ops.hpp"
#include "registry.hpp"
#include "filesystem.hpp"
#include "../../target.hpp"
#include <cstring>
#include <string>

struct win_kernel_state : kernel_state
{
	win_obj_manager objs;
	win_registry reg;
	win_filesystem fs;
	std::shared_ptr<win_kernel_proc> sys_proc;
	loaded_module_list_t loaded_module_list;
	active_process_list_t active_process_list;
	emu_object<_KUSER_SHARED_DATA> kuser_shared_data;

	// The two lists live in guest memory and a push_back rewrites the head and
	// the old tail, so concurrent module loads would tangle the guest's own
	// links. Public because win_kernel_proc appends to the module list.
	std::mutex list_mtx_;

	explicit win_kernel_state(const std::shared_ptr<class emu>& emu)
		:	objs(*emu->default_addr_space()),
			sys_proc(std::make_shared<win_kernel_proc>(objs.allocate_id(), *this, emu->default_addr_space()))
	{
		emu_ = emu;
		processes[sys_proc->id()] = sys_proc;
		auto& space = *emu->default_addr_space();

		fs.load_dir(target::guest_fs_dir, root_dir_narrow);

		if (const auto ntoskrnl = map_redirect_module(*sys_proc, std::string(target::guest_fs_dir) + "ntoskrnl.exe", true))
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
				if (active_process_list.address())
				{
					auto sys_eproc = insert_process(space, sys_proc->id(), "System");
					space.write_mem(*ps_init, sys_eproc.address());
				}
			}
		}

		space.mmu_->map_virt(space, kuser_shared_data_kernel_va,
			sizeof(_KUSER_SHARED_DATA), prot_rw | prot_supervisor);
		kuser_shared_data = emu_object<_KUSER_SHARED_DATA>(space, kuser_shared_data_kernel_va);
		kuser_shared_data.write(make_default_kuser_shared_data());
	}

	void set_emulator(windows_emulator* e) { emulator_ = e; }

	std::shared_ptr<process> create_process(const std::string_view name) override
	{
		std::unique_lock lock(proc_mtx_);
		const auto id = objs.allocate_id();
		auto& kspace = *emu_->default_addr_space();
		const auto kusd_pa = *kspace.mmu_->virt_to_phys(kspace, kuser_shared_data_kernel_va);
		auto proc = std::make_shared<win_user_proc>(id, emu_->mem()->create_addr_space(), objs, fs, kusd_pa, name);
		proc->set_emulator(emulator_);
		processes[id] = proc;

		if (active_process_list.address())
			insert_process(*emu_->default_addr_space(), id, name, proc->peb().address());

		return proc;
	}

private:
	windows_emulator* emulator_ = nullptr;
	emu_object<_EPROCESS> insert_process(addr_space& space, process::id_type id,
		std::string_view name, addr_t peb_address = 0)
	{
		_EPROCESS ep{};
		ep.UniqueProcessId = reinterpret_cast<void*>(static_cast<std::uintptr_t>(id));
		ep.Peb = reinterpret_cast<_PEB*>(static_cast<std::uintptr_t>(peb_address));
		std::memcpy(ep.ImageFileName, name.data(), std::min(name.size(), sizeof(ep.ImageFileName)));
		std::scoped_lock lock(list_mtx_);
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
		kernel_.sys_proc->set_emulator(this);
		kernel_.set_emulator(this);
		excp_ = std::make_shared<win::win_exception>(kernel_);
	}

	win_kernel_state& kernel() { return kernel_; }

	std::shared_ptr<thread> create_kernel_thread(vcpu& cpu, const addr_t start_addr) override
	{
		return kernel_.sys_proc->create_thread(cpu, start_addr);
	}

	virtual void init_thread_teb(thread&, vcpu&, addr_t) {}

private:
	win_kernel_state kernel_;
};
