#pragma once
#include "../emu/addr_space.hpp"
#include "../util/string.hpp"
#include <pe.hpp>

#include <atomic>
#include <map>
#include <unordered_map>
#include <string_view>
#include <string>
#include <optional>
#include <memory>
#include <mutex>

struct proc_module
{
	std::string name;
	addr_t addr;
	std::uint32_t size;
	addr_t entry_point;
	std::unordered_map<std::string, addr_t, string_view_hash, std::equal_to<>> exports;

	[[nodiscard]] std::optional<addr_t> find_export(const std::string_view exp_name)
	{
		const auto it = exports.find(exp_name);

		if (it == exports.end())
			return std::nullopt;

		return it->second;
	}
};

class vcpu;
class thread;
class thread_scheduler;

class process : public std::enable_shared_from_this<process>
{
public:
	using id_type = std::uint32_t;
	using thread_id_type = std::uint32_t;

	static constexpr std::size_t default_stack_size = 0x10000;

	process(const id_type id, std::shared_ptr<struct addr_space> space)
		:	id_(id), addr_space_(std::move(space)) { }

	virtual ~process() = default;
	virtual void module_add_cb([[maybe_unused]] proc_module& mod) { }

	std::shared_ptr<proc_module> add_module(std::string_view name, addr_t addr, const pe::image* pe);
	[[nodiscard]] std::shared_ptr<proc_module> find_module(std::string_view name) const;

	[[nodiscard]] std::shared_ptr<addr_space> addr_space() const;
	[[nodiscard]] id_type id() const { return id_; }

	void set_scheduler(thread_scheduler* s) { scheduler_ = s; }

	virtual std::shared_ptr<thread> create_thread(vcpu& cpu, addr_t start_addr);
	void terminate_thread(thread_id_type id);
	[[nodiscard]] std::shared_ptr<thread> find_thread(thread_id_type id) const;

	static thread_id_type alloc_thread_id() { return next_thread_id_++; }

protected:
	id_type id_;
	std::unordered_map<std::string_view, std::shared_ptr<proc_module>> modules_;
	std::shared_ptr<struct addr_space> addr_space_;
	thread_scheduler* scheduler_ = nullptr;
	mutable std::mutex thread_mtx_;
	std::map<thread_id_type, std::shared_ptr<thread>> threads_;

	static inline std::atomic<thread_id_type> next_thread_id_{1};
};
