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
#include "ethread.hpp"
#include "per_cpu.hpp"
#include "../../target.hpp"
#include <cstring>
#include <deque>
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

	// Every list the guest keeps lives in guest memory, and a push rewrites the
	// head and the old tail, so a module load or a thread starting at the same
	// time as another would tangle the guest's own links. Public because
	// win_kernel_proc appends to the module list and windows_process to the
	// per-process thread lists.
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

			if (active_process_list.address())
			{
				// The system process's own EPROCESS. Every kernel thread hangs
				// off the thread lists inside it, so it is worth having even
				// when nothing points the guest at it.
				const auto sys_eproc = insert_process(space, sys_proc->id(), "System");
				sys_proc->set_eprocess(sys_eproc);

				if (const auto ps_init = ntoskrnl->find_export("PsInitialSystemProcess"))
					space.write_mem(*ps_init, sys_eproc.address());
			}
		}

		space.mmu_->map_virt(space, kuser_shared_data_kernel_va,
			sizeof(_KUSER_SHARED_DATA), prot_rw | prot_supervisor);
		kuser_shared_data = emu_object<_KUSER_SHARED_DATA>(space, kuser_shared_data_kernel_va);
		kuser_shared_data.write(make_default_kuser_shared_data());
	}

	void set_emulator(windows_emulator* e) { emulator_ = e; }

	// Called once as each cpu is added, in the order they are added: that order
	// is what makes a block's index the cpu's own id.
	win_per_cpu& init_per_cpu(vcpu& cpu)
	{
		auto& pcpu = per_cpu_.emplace_back(*emu_->default_addr_space(),
			static_cast<std::uint32_t>(cpu.id()));

		// Where the guest looks to find out how many cpus the machine has.
		kuser_shared_data.space()->write_mem<std::uint32_t>(
			kuser_shared_data.address() + offsetof(_KUSER_SHARED_DATA, ActiveProcessorCount),
			static_cast<std::uint32_t>(per_cpu_.size()));

		return pcpu;
	}

	win_per_cpu* per_cpu(const std::size_t cpu_id)
	{
		return cpu_id < per_cpu_.size() ? &per_cpu_[cpu_id] : nullptr;
	}

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
		{
			const auto eproc = insert_process(*emu_->default_addr_space(), id, name,
				proc->peb().address());
			proc->set_eprocess(eproc);
		}

		return proc;
	}

private:
	windows_emulator* emulator_ = nullptr;

	// One KPCR per cpu, indexed by a cpu's id. A deque rather than a vector
	// because each block is handed out by pointer as its cpu is added.
	std::deque<win_per_cpu> per_cpu_;

	emu_object<_EPROCESS> insert_process(addr_space& space, process::id_type id,
		std::string_view name, addr_t peb_address = 0)
	{
		_EPROCESS ep{};
		ep.UniqueProcessId = reinterpret_cast<void*>(static_cast<std::uintptr_t>(id));
		ep.Peb = reinterpret_cast<_PEB*>(static_cast<std::uintptr_t>(peb_address));
		std::memcpy(ep.ImageFileName, name.data(), std::min(name.size(), sizeof(ep.ImageFileName)));

		std::scoped_lock lock(list_mtx_);
		auto obj = active_process_list.push_back(ep);

		// Empty circular lists, so the process's first thread has something to
		// link itself into.
		kprocess_thread_list(space, obj.address()).init();
		eprocess_thread_list(space, obj.address()).init();

		return obj;
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

	[[nodiscard]] win_per_cpu* per_cpu(const vcpu& cpu) { return kernel_.per_cpu(cpu.id()); }

	// Point the cpu's per-processor register at its own KPCR. Which register
	// that is belongs to the arch: the GS base on x86-64, TPIDR_EL1 on ARM64.
	virtual void set_pcr(vcpu&, addr_t) {}

	std::shared_ptr<thread> create_kernel_thread(vcpu& cpu, const addr_t start_addr) override
	{
		return kernel_.sys_proc->create_thread(cpu, start_addr);
	}

	virtual void init_thread_teb(thread&, vcpu&, addr_t) {}

private:
	win_kernel_state kernel_;
};
