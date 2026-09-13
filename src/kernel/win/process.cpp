#include "process.hpp"
#include "thread.hpp"
#include "win_kernel.hpp"
#include "../thread_scheduler.hpp"
#include "../../util/log.hpp"

win_kernel_proc::win_kernel_proc(id_type id, win_kernel_state& kernel, std::shared_ptr<struct addr_space> space)
	:	windows_process(id, std::move(space), kernel.objs, kernel.fs), kernel_(kernel) {}

addr_t windows_process::find_symbol(const std::string_view mod_name,
	const std::string_view sym) const
{
	if (const auto mod = find_module(mod_name))
	{
		if (const auto addr = mod->find_symbol(sym))
			return *addr;
	}

	LOG_ERR("{}!{} not found", mod_name, sym);
	return 0;
}

std::shared_ptr<thread> windows_process::create_thread(vcpu& cpu, const addr_t start_addr)
{
	const auto id = static_cast<thread_id_type>(objs_.allocate_id());

	// A kernel thread's stack is kernel memory in its own process's address
	// space, which for the system process is the kernel's.
	const addr_t stack_base = addr_space_->alloc(default_stack_size, prot_rw | prot_supervisor);
	auto self = std::static_pointer_cast<windows_process>(shared_from_this());
	auto t = std::make_shared<win_kernel_thread>(
		id, std::move(self), start_addr,
		stack_base, default_stack_size, cpu);

	t->set_emulator(emulator_);
	setup_ethread(t, start_addr);

	// On the queue last: another cpu can pick the thread up and run it to the
	// end the moment it is there, and retiring it needs to find it here.
	{
		std::unique_lock lock(thread_mtx_);
		threads_[t->id()] = t;
	}

	scheduler_->enqueue(cpu, t);
	return t;
}

std::shared_ptr<thread> win_user_proc::create_thread(vcpu& cpu, const addr_t start_addr)
{
	const auto id = static_cast<thread_id_type>(objs_.allocate_id());

	const addr_t stack_base = mem_.alloc(default_stack_size, prot_rw);
	auto self = std::static_pointer_cast<windows_process>(shared_from_this());
	auto t = std::make_shared<win_user_thread>(
		id, std::move(self), mem_, start_addr,
		stack_base, default_stack_size, cpu);

	t->set_emulator(emulator_);
	setup_ethread(t, start_addr);

	emulator_->init_thread_teb(*t, cpu, t->teb().address());

	{
		std::unique_lock lock(thread_mtx_);
		threads_[t->id()] = t;
	}

	scheduler_->enqueue(cpu, t);
	return t;
}

void windows_process::setup_ethread(const std::shared_ptr<win_thread>& t, const addr_t start_addr)
{
	if (!emulator_)
		return;

	auto& space = *emulator_->emu().default_addr_space();

	ethread_params p{};
	p.eprocess = eprocess_.address();
	p.start_addr = start_addr;
	p.teb = t->teb().address();
	p.stack_limit = t->stack_limit();
	p.stack_base = t->stack_base();
	p.process_id = id_;
	p.thread_id = t->id();
	p.system_thread = t->is_system_thread();

	const auto et = make_default_ethread(p);

	// Through the object manager, so a handle to the thread resolves to the
	// ETHREAD itself rather than to a body the guest cannot read.
	auto obj = emu_object<_ETHREAD>(space,
		objs_.create_object(0, &et, sizeof(et), std::make_shared<thread_object>(t),
			prot_rw | prot_supervisor));

	t->set_ethread(obj);

	// Both heads live in this process's EPROCESS, so a process the guest has no
	// view of has no lists to join.
	if (!eprocess_)
		return;

	auto& espace = *eprocess_.space();

	// The lists are the guest's own, and a push rewrites the head and the old
	// tail, so two threads starting at once would tangle the links.
	std::scoped_lock lock(emulator_->kernel().list_mtx_);

	kprocess_thread_list(espace, eprocess_.address()).push_back(obj);
	eprocess_thread_list(espace, eprocess_.address()).push_back(obj);

	auto active = eprocess_.field(&_EPROCESS::ActiveThreads);
	active.write(active.read() + 1);
}

void windows_process::destroy_ethread(const win_thread& t)
{
	const auto& et = t.ethread();

	if (!et || !emulator_)
		return;

	set_thread_state(et, Terminated, false);
	set_thread_exit_time(et, win_system_time());

	if (!eprocess_)
		return;

	auto& espace = *eprocess_.space();

	std::scoped_lock lock(emulator_->kernel().list_mtx_);

	kprocess_thread_list(espace, eprocess_.address()).remove(et.address());
	eprocess_thread_list(espace, eprocess_.address()).remove(et.address());

	auto active = eprocess_.field(&_EPROCESS::ActiveThreads);

	if (const auto count = active.read(); count > 0)
		active.write(count - 1);
}

void windows_process::terminate_thread(const thread_id_type id)
{
	// The guest keeps its own record of the thread, and it outlives the
	// scheduler's: nothing frees the ETHREAD, so it is only unlinked.
	if (const auto t = std::dynamic_pointer_cast<win_thread>(find_thread(id)))
		destroy_ethread(*t);

	process::terminate_thread(id);
}

std::shared_ptr<proc_module> windows_process::load_module(const std::string_view name, const bool supervisor)
{
	const auto path = std::string(system32_dir_narrow) + std::string(name);
	const auto file = fs_.open(path);

	if (!file)
		return nullptr;

	return krnl::map_img(*this, name, file->data(), supervisor);
}

std::shared_ptr<proc_module> win_user_proc::load_module(const std::string_view name, const bool supervisor)
{
	if (const auto file = fs_.open(current_dir_ + std::string(name)))
		return krnl::map_img(*this, name, file->data(), supervisor);

	return windows_process::load_module(name, supervisor);
}

void win_user_proc::module_add_cb(proc_module& mod)
{
	mem_.register_image(mod.addr, mod.size);

	ldr_.add_module(mem_, mod.addr, mod.entry_point,
		mod.size, mod.name, true);
}

void win_kernel_proc::module_add_cb(proc_module& mod)
{
	if (!kernel_.loaded_module_list.address())
		return;

	_KLDR_DATA_TABLE_ENTRY entry{};
	entry.DllBase = reinterpret_cast<void*>(mod.addr);
	entry.EntryPoint = reinterpret_cast<void*>(mod.entry_point);
	entry.SizeOfImage = mod.size;

	std::scoped_lock lock(kernel_.list_mtx_);
	const auto obj = kernel_.loaded_module_list.push_back(entry);

	// Keep where the entry landed: a driver reaches its own entry only through
	// its DRIVER_OBJECT, and nothing else remembers the address.
	kernel_.set_ldr_entry(mod.addr, obj.address());
}
