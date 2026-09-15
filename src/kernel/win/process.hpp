#pragma once
#include <functional>
#include "../process.hpp"
#include "../map.hpp"
#include "win_handle_table.hpp"
#include "win_user_mem.hpp"
#include "user_setup.hpp"
#include "ldr.hpp"
#include "process_params.hpp"

struct win_kernel_state;
class windows_emulator;
class win_thread;

// The stub a thread's start routine returns to. ntdll exports its one;
// ntoskrnl's is internal, so that one needs the ntoskrnl PDB.
constexpr std::string_view kernel_thread_startup = "PspSystemThreadStartup";
constexpr std::string_view user_thread_startup   = "RtlUserThreadStart";

constexpr std::string_view loader_thread_startup = "LdrInitializeThunk";

constexpr std::string_view user_exception_dispatcher = "KiUserExceptionDispatcher";

constexpr std::string_view ntdll_name = "ntdll.dll";

class windows_process : public process
{
public:
	windows_process(id_type id, std::shared_ptr<struct addr_space> space,
		win_obj_manager& objs, const win_filesystem& fs)
		:	process(id, std::move(space)), objs_(objs), handle_table_(objs), fs_(fs) {}

	std::shared_ptr<thread> create_thread(vcpu& cpu, addr_t start_addr,
		std::span<const std::uint64_t> args = {}) override;
	void terminate_thread(thread_id_type id) override;

	// The thread the ETHREAD belongs to, which is what a thread handle names.
	[[nodiscard]] std::shared_ptr<win_thread> find_ethread(
		const emu_object<_ETHREAD>& ethread) const;

	// Every windows thread of this process, for the things that have to look at
	// all of them: waking waiters, and finding one by its ETHREAD.
	void for_each_thread(const std::function<void(win_thread&)>& fn) const;

	// Hands `object` to whichever of this process's threads are parked on it
	// and can take it. Called by whoever signalled the object, because deciding
	// a wait means reading the objects and the scheduler is in no position to
	// do that -- it only notices that the answer is in.
	void wake_waiters(struct addr_space& space, addr_t object) const;

	win_handle_table& handle_table() { return handle_table_; }

	const emu_object<_PEB64>& peb() const { return peb_; }

	void set_emulator(windows_emulator* e) { emulator_ = e; }

	// The guest's own view of this process, and the anchor for its thread
	// lists. Unset when the guest has no view of it -- without ntoskrnl's
	// symbols there is no list to put it on.
	void set_eprocess(emu_object<_EPROCESS> ep) { eprocess_ = std::move(ep); }
	[[nodiscard]] const emu_object<_EPROCESS>& eprocess() const { return eprocess_; }

protected:
	// Where a module is looked for when the process has nowhere of its own.
	[[nodiscard]] std::shared_ptr<win_file> open_system_image(std::string_view name) const;

	// 0 if the module is not mapped or has no such symbol, logging either way.
	addr_t find_symbol(std::string_view mod_name, std::string_view sym) const;

	// Gives the thread the guest-side half of itself and links it into this
	// process's thread lists. Both create_thread paths call it once the thread
	// has the stack and TEB the ETHREAD describes.
	void setup_ethread(const std::shared_ptr<win_thread>& t, addr_t start_addr);

	// The other end: off the lists, and stamped with when it stopped.
	void destroy_ethread(const win_thread& t);

	win_obj_manager& objs_;
	win_handle_table handle_table_;
	emu_object<_PEB64> peb_;
	emu_object<_EPROCESS> eprocess_;
	windows_emulator* emulator_ = nullptr;
	const win_filesystem& fs_;
};

class win_user_proc : public windows_process
{
public:
	win_user_proc(id_type id, std::shared_ptr<struct addr_space> space,
		win_obj_manager& objs, const win_filesystem& fs,
		addr_t shared_data_pa, std::string_view image_path, std::size_t processors)
		:	windows_process(id, std::move(space), objs, fs), mem_(addr_space_)
	{
		auto& sp = *addr_space_;

		const auto wide_path = widen_string(image_path);
		const auto wide_dir = win::dir_from_path(wide_path);
		current_dir_ = narrow_wstring(wide_dir);

		image_name_ = ascii_lower(image_path.substr(wide_dir.size()));

		const auto peb_addr = mem_.alloc(peb64_alloc_size, prot_rw);
		peb_ = emu_object<_PEB64>(sp, peb_addr);
		peb_.write(make_default_peb(processors));

		const auto ldr_addr = mem_.alloc(sizeof(_PEB_LDR_DATA), prot_rw);
		ldr_ = ldr_module_list(mem_, ldr_addr);

		params_ = win::init_process_parameters(mem_, wide_path);

		sp.mmu_->map_virt_phys(sp, kuser_shared_data_user_va, shared_data_pa,
			sizeof(_KUSER_SHARED_DATA), prot_read);
		mem_.register_mapped(kuser_shared_data_user_va, sizeof(_KUSER_SHARED_DATA),
			win::page_readonly);

		auto api_sets = win::init_api_set_map(mem_, fs);
		api_sets_ = std::move(api_sets.map);

		auto peb = peb_.read();
		peb.Ldr = ldr_addr;
		peb.ProcessParameters = params_.address();
		peb.ApiSetMap = api_sets.address;
		peb.GdiSharedHandleTable = mem_.alloc(0x1000, prot_rw);
		peb_.write(peb);

		// A thread starts in ntdll's loader, so without it there is nothing to
		// start. Last, because mapping writes the loader list set up above.
		if (!win_user_proc::load_module(ntdll_name, false))
			LOG_ERR("{} is not in the guest filesystem", ntdll_name);
	}

	std::shared_ptr<proc_module> load_module(std::string_view name, bool supervisor) override;

	[[nodiscard]] std::string resolve_module_name(const std::string_view name,
		const std::string_view importer) const override
	{
		if (auto host = api_sets_.resolve(name, importer))
			return std::move(*host);

		return std::string(name);
	}

	void module_add_cb(proc_module& mod) override;

	std::shared_ptr<thread> create_thread(vcpu& cpu, addr_t start_addr,
		std::span<const std::uint64_t> args = {}) override;

	// The loader reads the image's PE headers through this; creating the
	// process heap needs the subsystem version out of them.
	void set_image_base(const addr_t base)
	{
		peb_.field(&_PEB64::ImageBaseAddress).write(base);
	}

	// Where GetStdHandle reads from, and with it everything the crt writes
	// through: a process handed none of these prints into nowhere.
	void set_std_handles(const win_handle_table::handle_t in,
		const win_handle_table::handle_t out, const win_handle_table::handle_t err)
	{
		const auto handle = [](const win_handle_table::handle_t h)
		{
			return reinterpret_cast<void*>(static_cast<std::uintptr_t>(h));
		};

		params_.field(&_RTL_USER_PROCESS_PARAMETERS::StandardInput).write(handle(in));
		params_.field(&_RTL_USER_PROCESS_PARAMETERS::StandardOutput).write(handle(out));
		params_.field(&_RTL_USER_PROCESS_PARAMETERS::StandardError).write(handle(err));
	}

	addr_t thread_exit_addr() const override
	{
		return find_symbol(ntdll_name, user_thread_startup);
	}

	win_user_mem& mem() { return mem_; }
	const win_user_mem& mem() const { return mem_; }

	[[nodiscard]] bool is_process_image(const proc_module& mod) const
	{
		return mod.lookup_name == image_name_;
	}

private:
	win_user_mem mem_;
	ldr_module_list ldr_;
	emu_object<_RTL_USER_PROCESS_PARAMETERS> params_;
	std::string current_dir_;
	std::string image_name_;
	win::api_set_map api_sets_;
};

class win_kernel_proc : public windows_process
{
public:
	win_kernel_proc(id_type id, win_kernel_state& kernel, std::shared_ptr<struct addr_space> space);

	addr_t thread_exit_addr() const override
	{
		return find_symbol("ntoskrnl.exe", kernel_thread_startup);
	}

	std::shared_ptr<proc_module> load_module(std::string_view name, bool supervisor) override;

	void module_add_cb(proc_module& mod) override;

private:
	win_kernel_state& kernel_;
};
