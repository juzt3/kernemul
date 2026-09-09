#pragma once
#include "../emu/addr_space.hpp"
#include <unordered_map>
#include <string_view>
#include <string>
#include <memory>

struct proc_module
{
	std::string name;
};

class process
{
public:
	virtual ~process() = default;

	virtual void module_add_cb([[maybe_unused]] proc_module& mod) { }

	std::shared_ptr<proc_module> add_module(std::string_view name);
	[[nodiscard]] std::shared_ptr<proc_module> find_module(std::string_view name) const;

	[[nodiscard]] std::shared_ptr<addr_space> addr_space() const;

protected:
	std::unordered_map<std::string_view, std::shared_ptr<proc_module>> modules_;
	std::shared_ptr<struct addr_space> addr_space_;
};

class user_process : public process
{

};

class kernel_process : public process
{
public:
	void module_add_cb(proc_module& mod) override;
};
