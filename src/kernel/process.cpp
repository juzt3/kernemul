#include "process.hpp"

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
