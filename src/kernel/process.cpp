#include "process.hpp"
#include "thread_scheduler.hpp"

std::shared_ptr<proc_module> process::add_module(const std::string_view name, const addr_t addr, const pe::image* const pe)
{
	auto mod = std::make_shared<proc_module>(std::string(name), addr, pe->size(), addr + pe->entry_point());

	module_add_cb(*mod);

	modules_[mod->name] = mod;

	for (const auto exp : pe->exports())
	{
		if (exp.is_ordinal)
			continue;

		mod->exports[std::string(exp.name)] = addr + exp.loc.rva();
	}

	return mod;
}

std::shared_ptr<proc_module> process::find_module(const std::string_view name) const
{
	const auto it = modules_.find(name);

	return it != modules_.end() ? it->second : nullptr;
}

std::shared_ptr<addr_space> process::addr_space() const
{
	return addr_space_;
}

std::shared_ptr<thread> process::create_thread(vcpu& cpu, const addr_t start_addr)
{
	auto t = scheduler_->create_thread(cpu, start_addr, shared_from_this());

	std::scoped_lock lock(thread_mtx_);
	threads_[t->id()] = t;
	return t;
}

void process::terminate_thread(const thread_id_type id)
{
	std::shared_ptr<thread> t;

	{
		std::scoped_lock lock(thread_mtx_);
		const auto it = threads_.find(id);
		if (it == threads_.end())
			return;
		t = it->second;
		threads_.erase(it);
	}

	if (scheduler_)
		scheduler_->remove(id);
}

std::shared_ptr<thread> process::find_thread(const thread_id_type id) const
{
	std::scoped_lock lock(thread_mtx_);
	const auto it = threads_.find(id);
	return it != threads_.end() ? it->second : nullptr;
}
