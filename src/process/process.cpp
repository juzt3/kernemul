#include "process.hpp"

std::shared_ptr<proc_module> process::add_module(const std::string_view name)
{
	const auto mod = std::make_shared<proc_module>(std::string(name));

	module_add_cb(*mod);

	modules_[name] = mod;

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

void kernel_process::module_add_cb(proc_module& mod)
{
			
}
