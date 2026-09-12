#pragma once
#include "../emu/defs.hpp"
#include "../util/string.hpp"

#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

struct proc_module;
class process;

struct symbol_info
{
	std::string name;
	addr_t addr;
	std::uint32_t size = 0;
};

struct resolved_symbol
{
	const symbol_info* symbol;
	std::uint32_t offset;

	[[nodiscard]] std::string format() const
	{
		if (offset == 0)
			return symbol->name;

		return std::format("{}+0x{:X}", symbol->name, offset);
	}
};

struct module_symbols
{
	std::vector<symbol_info> entries;

	// Maps to the address rather than an index into entries, because sort()
	// reorders entries and any stored index would silently go stale.
	std::unordered_map<std::string, addr_t, string_view_hash, std::equal_to<>> name_index;

	void insert(std::string name, addr_t addr, std::uint32_t size = 0);
	void sort();

	[[nodiscard]] std::optional<resolved_symbol> resolve(addr_t addr) const;
	[[nodiscard]] std::optional<addr_t> lookup(std::string_view name) const;

	[[nodiscard]] std::size_t size() const { return entries.size(); }
	[[nodiscard]] bool empty() const { return entries.empty(); }
};

struct symbols
{
	virtual ~symbols() = default;
	virtual void load(proc_module& mod) = 0;

	static std::string format_addr(const process& proc, addr_t addr);
};

struct export_symbols : symbols
{
	void load(proc_module& mod) override;
};
