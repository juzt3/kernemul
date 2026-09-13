#pragma once
#include <span>
#include "../emu/addr_space.hpp"
#include "../sym/symbol.hpp"
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
#include <shared_mutex>

struct proc_module
{
	std::string name;
	addr_t addr;
	std::uint32_t size;
	addr_t entry_point;
	std::vector<std::uint8_t> image;
	std::unordered_map<std::string, addr_t, string_view_hash, std::equal_to<>> exports;
	module_symbols symbols;

	[[nodiscard]] const pe::image* pe() const
	{
		return image.empty() ? nullptr : reinterpret_cast<const pe::image*>(image.data());
	}

	[[nodiscard]] std::optional<addr_t> find_export(const std::string_view exp_name) const
	{
		const auto it = exports.find(exp_name);

		if (it == exports.end())
			return std::nullopt;

		return it->second;
	}

	[[nodiscard]] std::optional<addr_t> find_symbol(const std::string_view sym_name) const
	{
		if (!symbols.empty())
			return symbols.lookup(sym_name);

		return find_export(sym_name);
	}

	[[nodiscard]] bool contains_addr(addr_t a) const
	{
		return a >= addr && a < addr + size;
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
	static constexpr std::size_t stack_reserve = 0x100;

	process(const id_type id, std::shared_ptr<struct addr_space> space)
		:	id_(id), addr_space_(std::move(space)) { }

	virtual ~process() = default;
	virtual void module_add_cb([[maybe_unused]] proc_module& mod) { }

	std::shared_ptr<proc_module> add_module(std::string_view name, addr_t addr, const pe::image* pe);
	[[nodiscard]] std::shared_ptr<proc_module> find_module(std::string_view name) const;
	[[nodiscard]] std::shared_ptr<proc_module> find_module_by_addr(addr_t addr) const;

	[[nodiscard]] std::shared_ptr<addr_space> addr_space() const;
	[[nodiscard]] id_type id() const { return id_; }

	void set_scheduler(thread_scheduler* s) { scheduler_ = s; }

	// The arguments go in before the thread is queued: a thread is runnable the
	// moment it is on the queue, and another cpu will start it. Setting them
	// afterwards is a race against a thread that may already be running.
	virtual std::shared_ptr<thread> create_thread(vcpu& cpu, addr_t start_addr,
		std::span<const std::uint64_t> args = {});

	// The start stub a thread's start routine returns to. Windows starts a
	// thread inside one of these and it ends the thread when the routine
	// returns; reaching it is how the emulator sees the same thing.
	[[nodiscard]] virtual addr_t thread_exit_addr() const { return 0; }
	virtual void terminate_thread(thread_id_type id);
	[[nodiscard]] std::shared_ptr<thread> find_thread(thread_id_type id) const;

	static thread_id_type alloc_thread_id() { return next_thread_id_++; }

protected:
	id_type id_;
	// Read on every symbol lookup and every fault, written only when a module
	// is mapped.
	mutable std::shared_mutex modules_mtx_;
	std::unordered_map<std::string_view, std::shared_ptr<proc_module>> modules_;
	std::shared_ptr<struct addr_space> addr_space_;
	thread_scheduler* scheduler_ = nullptr;
	mutable std::shared_mutex thread_mtx_;
	std::map<thread_id_type, std::shared_ptr<thread>> threads_;

	static inline std::atomic<thread_id_type> next_thread_id_{1};
};
