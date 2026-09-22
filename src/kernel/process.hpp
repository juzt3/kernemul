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

	// Windows resolves imports case-insensitively -- FLTMGR.SYS is as common as fltmgr.sys.
	std::string lookup_name;
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

	// An ordinal is the function table's index counted from the directory's base.
	[[nodiscard]] std::optional<addr_t> find_ordinal(const std::uint32_t ordinal) const
	{
		const auto* const img = pe();

		if (!img)
			return std::nullopt;

		const auto& dir = img->nt_hdrs()->optional_hdr.data_dirs.exports;

		if (!dir.used())
			return std::nullopt;

		const auto* const bytes = img->as<const std::uint8_t*>();
		const auto* const exp = reinterpret_cast<const pe::export_directory*>(
			bytes + dir.virtual_address);

		if (ordinal < exp->base || ordinal - exp->base >= exp->number_of_functions)
			return std::nullopt;

		const auto rva = reinterpret_cast<const std::uint32_t*>(
			bytes + exp->address_of_functions)[ordinal - exp->base];

		// An rva inside the export directory is a forwarder, not code; an unused slot is zero.
		if (!rva || (rva >= dir.virtual_address && rva < dir.virtual_address + dir.size))
			return std::nullopt;

		return addr + rva;
	}

	[[nodiscard]] std::string_view find_forward(const std::string_view exp_name) const
	{
		const auto* const img = pe();

		if (!img)
			return {};

		for (const auto exp : img->exports())
		{
			if (exp.forwarded && exp.name == exp_name)
				return exp.loc.addr<const char*>();
		}

		return {};
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

	// A pe forwarder writes "ntoskrnl.KeFoo", never the extension, so it matches on the stem.
	[[nodiscard]] std::shared_ptr<proc_module> find_module_by_stem(std::string_view stem) const;

	virtual std::shared_ptr<proc_module> load_module(std::string_view, bool) { return nullptr; }

	// api-ms-* and ext-ms-* name contracts, not files; the schema says which file keeps each.
	[[nodiscard]] virtual std::string resolve_module_name(const std::string_view name,
		std::string_view /*importer*/) const
	{
		return std::string(name);
	}

	[[nodiscard]] std::shared_ptr<addr_space> addr_space() const;
	[[nodiscard]] id_type id() const { return id_; }

	void set_scheduler(thread_scheduler* s) { scheduler_ = s; }
	[[nodiscard]] thread_scheduler* scheduler() const noexcept { return scheduler_; }

	// Made but held off the cpu, so whoever asked for it can finish it -- write the frame it
	// starts on, put an argument in place -- before start() lets a cpu pick it up. Arguments
	// passed here go in before that, since a started thread is another cpu's to run.
	virtual std::shared_ptr<thread> create_suspended_thread(vcpu& cpu, addr_t start_addr,
		std::span<const std::uint64_t> args = {}, std::size_t stack_size = 0);

	// The same thread, started: nothing else needs to happen to it before it runs.
	std::shared_ptr<thread> create_thread(vcpu& cpu, addr_t start_addr,
		std::span<const std::uint64_t> args = {}, std::size_t stack_size = 0);

	// What a thread stack ends up being: what was asked for, rounded up to a page, never below
	// the default and never above the cap, since the whole of it is committed up front.
	static constexpr std::size_t max_stack_size = 0x100000;

	static constexpr std::size_t thread_stack_size(const std::size_t wanted)
	{
		const auto pages = (std::max(wanted, default_stack_size) + 0xFFF) & ~std::size_t(0xFFF);
		return std::min(pages, max_stack_size);
	}

	// Windows starts a thread inside one of these and it ends the thread when the routine returns.
	[[nodiscard]] virtual addr_t thread_exit_addr() const { return 0; }
	virtual void terminate_thread(thread_id_type id);
	[[nodiscard]] std::shared_ptr<thread> find_thread(thread_id_type id) const;

	// Every thread in the process, for an operation that applies to all of them at once.
	[[nodiscard]] std::vector<std::shared_ptr<thread>> threads() const
	{
		std::shared_lock lock(thread_mtx_);

		std::vector<std::shared_ptr<thread>> out;
		out.reserve(threads_.size());

		for (const auto& [id, t] : threads_)
			out.push_back(t);

		return out;
	}

	static thread_id_type alloc_thread_id() { return next_thread_id_++; }

protected:
	id_type id_;
	mutable std::shared_mutex modules_mtx_;
	std::unordered_map<std::string_view, std::shared_ptr<proc_module>> modules_;
	std::shared_ptr<struct addr_space> addr_space_;
	thread_scheduler* scheduler_ = nullptr;
	mutable std::shared_mutex thread_mtx_;
	std::map<thread_id_type, std::shared_ptr<thread>> threads_;

	static inline std::atomic<thread_id_type> next_thread_id_{1};
};
