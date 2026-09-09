#pragma once
#include "../emu/addr_space.hpp"
#include "../util/string.hpp"
#include <pe.hpp>

#include <unordered_map>
#include <string_view>
#include <string>
#include <optional>
#include <memory>

struct proc_module
{
	std::string name;
	addr_t addr;
	std::unordered_map<std::string, addr_t, string_view_hash, std::equal_to<>> exports;

	[[nodiscard]] std::optional<addr_t> find_export(const std::string_view exp_name)
	{
		const auto it = exports.find(exp_name);

		if (it == exports.end())
			return std::nullopt;

		return it->second;
	}
};

class process
{
public:
	using id_type = std::uint32_t;

	explicit process(const id_type id)
		:	id_(id) { }

	virtual ~process() = default;
	virtual void module_add_cb([[maybe_unused]] proc_module& mod) { }

	std::shared_ptr<proc_module> add_module(std::string_view name, addr_t addr, const pe::image* pe);
	[[nodiscard]] std::shared_ptr<proc_module> find_module(std::string_view name) const;

	[[nodiscard]] std::shared_ptr<addr_space> addr_space() const;
	[[nodiscard]] id_type id() const { return id_; }

protected:
	id_type id_;
	std::unordered_map<std::string_view, std::shared_ptr<proc_module>> modules_;
	std::shared_ptr<struct addr_space> addr_space_;
};

class user_process : public process
{
public:
	using process::process;
};

class kernel_process : public process
{
public:
	using process::process;
	void module_add_cb(proc_module& mod) override;
};
