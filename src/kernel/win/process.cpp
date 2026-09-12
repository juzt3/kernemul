#include "process.hpp"
#include "thread.hpp"
#include "win_kernel.hpp"
#include "../thread_scheduler.hpp"

win_kernel_proc::win_kernel_proc(id_type id, win_kernel_state& kernel, std::shared_ptr<struct addr_space> space)
	:	windows_process(id, std::move(space), kernel.objs, kernel.fs), kernel_(kernel) {}

std::shared_ptr<thread> windows_process::create_thread(vcpu& cpu, const addr_t start_addr)
{
	const auto id = static_cast<thread_id_type>(objs_.allocate_id());
	auto t = scheduler_->create_thread(cpu, start_addr, shared_from_this(), id);

	std::scoped_lock lock(thread_mtx_);
	threads_[t->id()] = t;
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

	emulator_->init_thread_segments(*t, cpu, t->teb().address());

	scheduler_->enqueue(t);

	std::scoped_lock lock(thread_mtx_);
	threads_[t->id()] = t;
	return t;
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

	kernel_.loaded_module_list.push_back(entry);
}
