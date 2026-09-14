#include "process.hpp"
#include "thread_scheduler.hpp"
#include "../sym/pdb.hpp"
#include <ranges>

std::shared_ptr<proc_module> process::add_module(const std::string_view name, const addr_t addr, const pe::image* const pe)
{
	auto mod = std::make_shared<proc_module>();
	mod->name = std::string(name);
	mod->lookup_name = ascii_lower(name);
	mod->addr = addr;
	mod->size = pe->size();
	mod->entry_point = addr + pe->entry_point();
	mod->image.assign(pe->as<const std::uint8_t*>(), pe->as<const std::uint8_t*>() + pe->size());

	module_add_cb(*mod);

	{
		std::unique_lock lock(modules_mtx_);
		modules_[mod->lookup_name] = mod;
	}

	// A forwarded export has the name of another module's where its code would
	// be, so there is no address to record for it -- find_forward reads the
	// name back out of the image if something imports it.
	for (const auto exp : pe->exports())
	{
		if (!exp.forwarded)
			mod->exports[std::string(exp.name)] = addr + exp.loc.rva();
	}

	export_symbols{}.load(*mod);
	pdb_symbols{}.load(*mod);

	return mod;
}

std::shared_ptr<proc_module> process::find_module(const std::string_view name) const
{
	const auto key = ascii_lower(name);

	std::shared_lock lock(modules_mtx_);

	const auto it = modules_.find(key);

	return it != modules_.end() ? it->second : nullptr;
}

std::shared_ptr<proc_module> process::find_module_by_addr(const addr_t addr) const
{
	std::shared_lock lock(modules_mtx_);

	for (const auto& mod : modules_ | std::views::values)
		if (mod->contains_addr(addr))
			return mod;

	return nullptr;
}

std::shared_ptr<addr_space> process::addr_space() const
{
	return addr_space_;
}

std::shared_ptr<thread> process::create_thread(vcpu& cpu, const addr_t start_addr,
	const std::span<const std::uint64_t> args)
{
	const auto id = alloc_thread_id();
	auto t = scheduler_->create_thread(cpu, start_addr, shared_from_this(), id, args);

	std::unique_lock lock(thread_mtx_);
	threads_[t->id()] = t;
	return t;
}

void process::terminate_thread(const thread_id_type id)
{
	std::shared_ptr<thread> t;

	{
		std::unique_lock lock(thread_mtx_);
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
	std::shared_lock lock(thread_mtx_);
	const auto it = threads_.find(id);
	return it != threads_.end() ? it->second : nullptr;
}
