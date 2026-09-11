#pragma once
#include "../emu/defs.hpp"

#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct proc_module;
class process;

struct symbol_info
{
	std::string name;
	addr_t addr;
	std::uint32_t size = 0;
};

using module_symbols = std::vector<symbol_info>;

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

struct symbols
{
	virtual ~symbols() = default;
	virtual void load(proc_module& mod) = 0;

	static std::optional<resolved_symbol> resolve(const module_symbols& syms, addr_t addr);
	static std::optional<addr_t> lookup(const module_symbols& syms, std::string_view name);
	static void sort(module_symbols& syms);
	static std::string format_addr(const process& proc, addr_t addr);
};

struct export_symbols : symbols
{
	void load(proc_module& mod) override;
};
