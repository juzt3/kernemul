#include "process.hpp"
#include "win_kernel.hpp"
#include "../thread_scheduler.hpp"

win_kernel_proc::win_kernel_proc(id_type id, win_kernel_state& kernel, std::shared_ptr<struct addr_space> space)
	:	windows_process(id, std::move(space), kernel.objs), kernel_(kernel) {}

std::shared_ptr<thread> windows_process::create_thread(vcpu& cpu, const addr_t start_addr)
{
	const auto id = static_cast<thread_id_type>(objs_.allocate_id());
	auto t = scheduler_->create_thread(cpu, start_addr, shared_from_this(), id);

	std::scoped_lock lock(thread_mtx_);
	threads_[t->id()] = t;
	return t;
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
