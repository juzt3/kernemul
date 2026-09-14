#pragma once
#include "../kernel.hpp"
#include "../../sym/symbol.hpp"
#include "process.hpp"
#include "exception.hpp"
#include "defs.hpp"
#include "modules/ntoskrnl.hpp"
#include "registry.hpp"
#include "filesystem.hpp"
#include "ethread.hpp"
#include "driver.hpp"
#include "per_cpu.hpp"
#include "objects.hpp"
#include "modules/fltmgr.hpp"
#include "modules/cng.hpp"
#include "modules/ci.hpp"
#include "modules/ndis.hpp"
#include "modules/tbs.hpp"
#include "modules/tdi.hpp"
#include "modules/win32k.hpp"
#include "pool.hpp"
#include "syscalls.hpp"
#include "status.hpp"
#include "../../emu/guest_call.hpp"
#include "../../target.hpp"
#include <cstring>
#include <filesystem>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>

struct win_kernel_state : kernel_state
{
	win_obj_manager objs;
	win_pool pool;
	win_registry reg;
	win_filesystem fs;
	std::shared_ptr<win_kernel_proc> sys_proc;
	loaded_module_list_t loaded_module_list;
	active_process_list_t active_process_list;
	emu_object<_KUSER_SHARED_DATA> kuser_shared_data;

	// One table per machine, built at boot. Null where there is no
	// implementation for the architecture.
	std::unique_ptr<win_syscall> syscalls = make_win_syscall();

	// One per machine: the trampoline it returns through is a single address.
	guest_caller calls;

	// Views mapped into system space, by base address, so unmapping one knows
	// how much to take down. Small and touched only by the two handlers that
	// map and unmap, so it rides with the rest of the kernel state.
	std::unordered_map<addr_t, std::uint64_t> views;

	// When the kernel came up, which is what a caller asking how long the
	// machine has been running measures against.
	std::int64_t boot_time = static_cast<std::int64_t>(win_system_time());

	// Every list the guest keeps lives in guest memory, and a push rewrites the
	// head and the old tail, so a module load or a thread starting at the same
	// time as another would tangle the guest's own links. Public because
	// win_kernel_proc appends to the module list and windows_process to the
	// per-process thread lists.
	std::mutex list_mtx_;

	explicit win_kernel_state(const std::shared_ptr<class emu>& emu)
		:	objs(*emu->default_addr_space()),
			pool(*emu->default_addr_space()),
			sys_proc(std::make_shared<win_kernel_proc>(objs.allocate_id(), *this, emu->default_addr_space()))
	{
		emu_ = emu;
		processes[sys_proc->id()] = sys_proc;
		auto& space = *emu->default_addr_space();

		// A flat directory on the host, mounted where a user process looks for
		// its DLLs.
		fs.load_dir(target::guest_fs_dir, system32_dir_narrow);

		const auto ntoskrnl = map_redirect_module("ntoskrnl.exe", modules::register_ntoskrnl);

		if (ntoskrnl)
		{
			// The modules beside it, each mapped only so a driver importing
			// from it can be told what its exports do.
			map_redirect_module("fltmgr.sys", modules::register_fltmgr);
			map_redirect_module("cng.sys", modules::register_cng);
			map_redirect_module("ci.dll", modules::register_ci);
			map_redirect_module("ndis.sys", modules::register_ndis);
			map_redirect_module("tbs.sys", modules::register_tbs);
			map_redirect_module("tdi.sys", modules::register_tdi);
			map_redirect_module("win32k.sys", modules::register_win32k);

			if (const auto ps_list = ntoskrnl->find_export("PsLoadedModuleList"))
			{
				loaded_module_list = loaded_module_list_t(space, *ps_list);
				loaded_module_list.init();
				sys_proc->module_add_cb(*ntoskrnl);
			}

			if (const auto ps_active = ntoskrnl->find_symbol("PsActiveProcessHead"))
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

			build_syscall_table(*ntoskrnl);
		}

		space.mmu_->map_virt(space, kuser_shared_data_kernel_va,
			sizeof(_KUSER_SHARED_DATA), prot_rw | prot_supervisor);
		kuser_shared_data = emu_object<_KUSER_SHARED_DATA>(space, kuser_shared_data_kernel_va);
		kuser_shared_data.write(make_default_kuser_shared_data());
	}

	// One of the kernel's own modules, mapped out of the guest filesystem with
	// the handlers that stand in for its exports. Nothing in a mapped module is
	// ever executed -- it is there so its exports have addresses to redirect --
	// which is why the imports are not resolved either.
	//
	// A module that is not in the guest filesystem is skipped rather than
	// fatal: a driver importing from it fails to map and says so, and one that
	// does not is unaffected.
	template <typename F>
	std::shared_ptr<proc_module> map_redirect_module(const std::string_view name, F&& registrar)
	{
		const auto path = std::string(target::guest_fs_dir) + std::string(name);

		if (!std::filesystem::exists(path))
		{
			LOG_WARN("{} is not in {}, so nothing importing from it will map",
				name, target::guest_fs_dir);
			return nullptr;
		}

		const auto mod = kernel_state::map_redirect_module(*sys_proc, path, true);

		if (!mod)
		{
			LOG_ERR("failed to map {}", name);
			return nullptr;
		}

		registrar(*this, *mod);

		return mod;
	}

	// Nt and Zw name one function at one address. Which of the two ntoskrnl
	// exports varies from one function to the next -- and a driver can only
	// import a name that is exported -- so a handler is bound to both spellings,
	// and only a pair where neither resolves is worth reporting.
	template <typename F>
	void redirect_ntzw(proc_module& mod, const std::string_view base, F&& fn)
	{
		const auto nt = "Nt" + std::string(base);
		const auto zw = "Zw" + std::string(base);
		const auto conv = emu_->call_conv();

		const bool bound_nt = try_redirect(mod, nt, make_redirect(conv, fn));
		const bool bound_zw = try_redirect(mod, zw, make_redirect(conv, fn));

		if (!bound_nt && !bound_zw)
			LOG_ERR("neither {} nor {} is in {}", nt, zw, mod.name);
	}

	void set_emulator(windows_emulator* e) { emulator_ = e; }
	[[nodiscard]] windows_emulator* emulator() const noexcept { return emulator_; }

	void build_syscall_table(const proc_module& ntoskrnl)
	{
		if (!syscalls)
			return;

		add_stub_services("ntdll.dll", ntoskrnl);

		if (const auto win32k = sys_proc->find_module("win32k.sys"))
			add_stub_services("win32u.dll", *win32k);
	}

	// Parsed in host memory: nothing ever runs these stubs, so the guest has no
	// reason to have them.
	void add_stub_services(const std::string_view name, const proc_module& impl)
	{
		const auto file = fs.open(std::string(system32_dir_narrow) + std::string(name));

		if (!file)
		{
			LOG_WARN("{} is not in the guest filesystem, so its services have no numbers",
				name);
			return;
		}

		const auto image = krnl::pe_virtual_image(file->data());

		if (image.empty())
		{
			LOG_WARN("{} is not a pe image, so its services have no numbers", name);
			return;
		}

		syscalls->add(name, image, impl);
	}

	// Only ever serves a log line, so it never throws.
	[[nodiscard]] std::string syscall_caller(vcpu& cpu) const
	{
		const auto t = cpu.thread();
		const auto proc = t ? std::dynamic_pointer_cast<windows_process>(t->proc()) : nullptr;

		if (!proc)
			return "an unknown caller";

		try
		{
			return symbols::format_addr(*proc, cpu.read_virt_mem<addr_t>(cpu.sp()));
		}
		catch (const std::exception&)
		{
			return "an unreadable stack";
		}
	}

	// The service number names an address in ntoskrnl or win32k, which is what
	// the handler was bound to -- so a trap lands on the same function a driver
	// calling that name would reach. Returns whether the handler moved the pc.
	//
	// Nothing changes mode: the handler is native, so the guest stays in ring 3.
	bool dispatch_syscall(vcpu& cpu)
	{
		const auto saved_pc = cpu.pc();
		const auto id = syscalls ? syscalls->id(cpu) : 0;
		const auto handler = syscalls ? syscalls->find(id) : std::nullopt;
		const auto* fn = handler ? find_redirect(*handler) : nullptr;

		if (!fn)
		{
			// Unlike an unimplemented export this does not end the thread: the
			// guest asked and gets an answer it knows how to deal with.
			THREAD_LOG_WARN("unimplemented syscall 0x{:X}, called from {}", id,
				syscall_caller(cpu));
			emu_->call_conv()->ret(cpu, static_cast<NTSTATUS>(STATUS_NOT_IMPLEMENTED));
			return false;
		}

		try
		{
			(*fn)(cpu);
		}
		catch (const std::exception& e)
		{
			THREAD_LOG_ERR("syscall 0x{:X} faulted: {}", id, e.what());
		}

		// A handler that moved the pc -- NtContinue, a thread ending -- has said
		// where to go, and stepping past the instruction would undo it.
		return cpu.pc() != saved_pc;
	}

	// A thread handle names the ETHREAD rather than the thread, so this is how
	// a handle gets back to the thread it belongs to.
	[[nodiscard]] std::shared_ptr<win_thread> find_ethread(const emu_object<_ETHREAD>& ethread)
	{
		if (!ethread)
			return {};

		std::shared_lock lock(proc_mtx_);

		for (const auto& [id, proc] : processes)
		{
			const auto win_proc = std::dynamic_pointer_cast<windows_process>(proc);

			if (!win_proc)
				continue;

			if (auto t = win_proc->find_ethread(ethread))
				return t;
		}

		return {};
	}

	// A module's entry in PsLoadedModuleList, by the address it was mapped at.
	// Only the driver object needs one, and only to point DriverSection at it,
	// but the entry is built as the module is added and nothing else keeps it.
	void set_ldr_entry(const addr_t base, const addr_t entry) { ldr_entries_[base] = entry; }

	[[nodiscard]] addr_t ldr_entry(const addr_t base) const
	{
		const auto it = ldr_entries_.find(base);
		return it != ldr_entries_.end() ? it->second : 0;
	}

	// The DRIVER_OBJECT and registry path DriverEntry is called with. Windows
	// builds both before it calls a driver, and a driver that is handed neither
	// has nowhere to put its unload routine or its dispatch table.
	struct driver_entry_args
	{
		emu_object<_DRIVER_OBJECT> driver_object;
		emu_object<_UNICODE_STRING> registry_path;
	};

	driver_entry_args create_driver(proc_module& mod, const std::u16string_view service_name)
	{
		auto& space = *emu_->default_addr_space();

		const auto drv = make_default_driver_object({
			.driver_name = win::init_unicode_string(space,
				std::u16string(driver_name_prefix) + std::u16string(service_name)),
			.driver_start = mod.addr,
			.driver_size = mod.size,
			.driver_section = ldr_entry(mod.addr),
			.driver_init = mod.entry_point,
		});

		// A driver object is an object manager object, so it goes through the
		// manager and gets a header the guest can dereference like any other.
		const auto body = objs.create_object(0, &drv, sizeof(drv),
			{}, prot_rw | prot_supervisor);

		emu_object<_DRIVER_OBJECT> obj(space, body, std::string(mod.name));

		auto reg_path = win::allocate_unicode_string(space,
			std::u16string(driver_services_key) + std::u16string(service_name), "RegistryPath");

		LOG_INFO("driver object for {} at 0x{:X} (section=0x{:X}, registry path at 0x{:X})",
			mod.name, obj.address(), ldr_entry(mod.addr), reg_path.address());

		return { std::move(obj), std::move(reg_path) };
	}

	// Called once as each cpu is added, in the order they are added: that order
	// is what makes a block's index the cpu's own id.
	win_per_cpu& init_per_cpu(vcpu& cpu)
	{
		auto& pcpu = per_cpu_.emplace_back(*emu_->default_addr_space(),
			static_cast<std::uint32_t>(cpu.id()));

		// Where the guest looks to find out how many cpus the machine has.
		kuser_shared_data.field(&_KUSER_SHARED_DATA::ActiveProcessorCount)
			.write(static_cast<std::uint32_t>(per_cpu_.size()));

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

	std::unordered_map<addr_t, addr_t> ldr_entries_;

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

		// Unbounded: start > end.
		emu_->hook_insn(1, 0, hook_insn_t::syscall,
			[this](vcpu& cpu) { return kernel_.dispatch_syscall(cpu); });
	}

	win_kernel_state& kernel() { return kernel_; }

	[[nodiscard]] win_per_cpu* per_cpu(const vcpu& cpu) { return kernel_.per_cpu(cpu.id()); }

	// Point the cpu's per-processor register at its own KPCR. Which register
	// that is belongs to the arch: the GS base on x86-64, TPIDR_EL1 on ARM64.
	virtual void set_pcr(vcpu&, addr_t) {}

	// Mirror the IRQL into whatever the architecture lets the guest read it
	// from without asking. x86-64 has cr8; ARM64 has nothing of the sort, so
	// there the KPCR is the only copy and this does nothing.
	virtual void set_hw_irql(vcpu&, irql_t) {}

	// A thread's registers as the guest's own CONTEXT, and the way back. Its
	// shape belongs to the architecture, so both halves live there. `flags` is
	// what was asked for; ContextFlags comes back saying what was filled in.
	virtual void capture_context(const reg_view& regs, emu_object<_CONTEXT> out,
		std::uint32_t flags) = 0;

	// Everything the architecture can fill in, for a caller with no request.
	static constexpr std::uint32_t context_all = ~0u;

	virtual void apply_context(const reg_view& regs, emu_object<_CONTEXT> in) = 0;

	// Raise or lower this cpu's IRQL, and say what it was. Every handler that
	// moves the IRQL goes through here, so the two copies cannot drift.
	irql_t set_irql(vcpu& cpu, const irql_t irql)
	{
		const auto* pcpu = per_cpu(cpu);

		if (!pcpu)
			return passive_level;

		const auto old = pcpu->irql();
		pcpu->set_irql(irql);
		set_hw_irql(cpu, irql);

		return old;
	}

	[[nodiscard]] irql_t irql(vcpu& cpu)
	{
		const auto* pcpu = per_cpu(cpu);
		return pcpu ? pcpu->irql() : passive_level;
	}

	std::shared_ptr<thread> create_kernel_thread(vcpu& cpu, const addr_t start_addr) override
	{
		return kernel_.sys_proc->create_thread(cpu, start_addr);
	}

	virtual void init_thread_teb(thread&, vcpu&, addr_t) {}

	// The CONTEXT and frame ntdll's LdrInitializeThunk starts on.
	virtual void setup_loader_frame(thread&, vcpu&, addr_t, addr_t) {}

	struct user_process_args
	{
		std::shared_ptr<win_user_proc> proc;
		std::shared_ptr<proc_module> image;
		std::shared_ptr<thread> thread;
	};

	// Brings up a process around `exe_name` and leaves its first thread queued.
	//
	// The thread starts at ntdll's LdrInitializeThunk, not at the image's entry
	// point: the loader creates the process heap, the TLS slots and the loader
	// locks that the image's startup code assumes exist, then reaches the entry
	// point by continuing through the context set up here.
	user_process_args create_user_process(vcpu& cpu, const std::string_view exe_name)
	{
		auto proc = std::dynamic_pointer_cast<win_user_proc>(
			kernel_.create_process(exe_name));

		if (!proc)
		{
			LOG_ERR("failed to create a process for {}", exe_name);
			return {};
		}

		proc->set_scheduler(&scheduler_);

		const auto ntdll = proc->find_module(ntdll_name);

		if (!ntdll)
		{
			LOG_ERR("{} is not in {}, so no user process can start",
				ntdll_name, target::guest_fs_dir);
			return {};
		}

		const auto image = proc->load_module(exe_name, false);

		if (!image)
		{
			LOG_ERR("{} is not in {}", exe_name, target::guest_fs_dir);
			return {};
		}

		proc->set_image_base(image->addr);

		const auto ldr_init = ntdll->find_symbol(loader_thread_startup);

		if (!ldr_init)
		{
			LOG_ERR("{}!{} not found", ntdll_name, loader_thread_startup);
			return {};
		}

		// Writing the frame after create_thread is safe only because no cpu is
		// running yet.
		auto t = proc->create_thread(cpu, *ldr_init);

		if (!t)
			return {};

		setup_loader_frame(*t, cpu, image->entry_point, ntdll->addr);

		LOG_INFO("user process {} (pid={}): image at 0x{:X}, entry 0x{:X}, loader at 0x{:X}",
			exe_name, proc->id(), image->addr, image->entry_point, *ldr_init);

		return { std::move(proc), image, std::move(t) };
	}

private:
	win_kernel_state kernel_;
};
