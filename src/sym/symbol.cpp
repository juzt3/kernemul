#include "symbol.hpp"
#include "../kernel/process.hpp"

#include <algorithm>
#include <format>

std::optional<resolved_symbol> symbols::resolve(const module_symbols& syms, const addr_t addr)
{
	if (syms.empty())
		return std::nullopt;

	auto it = std::ranges::upper_bound(syms, addr, {}, &symbol_info::addr);

	if (it == syms.begin())
		return std::nullopt;

	--it;

	const auto offset = static_cast<std::uint32_t>(addr - it->addr);

	if (it->size > 0 && offset >= it->size)
		return std::nullopt;

	return resolved_symbol{ &*it, offset };
}

std::optional<addr_t> symbols::lookup(const module_symbols& syms, const std::string_view name)
{
	auto it = std::ranges::find(syms, name, &symbol_info::name);

	if (it == syms.end())
		return std::nullopt;

	return it->addr;
}

void symbols::sort(module_symbols& syms)
{
	std::ranges::sort(syms, {}, &symbol_info::addr);
}

void export_symbols::load(proc_module& mod)
{
	for (const auto& [name, addr] : mod.exports)
		mod.symbols_.push_back({ name, addr, 0 });

	symbols::sort(mod.symbols_);
}

std::string symbols::format_addr(const process& proc, const addr_t addr)
{
	const auto mod = proc.find_module_by_addr(addr);

	if (!mod)
		return std::format("0x{:X}", addr);

	const auto sym = resolve(mod->symbols_, addr);

	if (!sym)
		return std::format("{}+0x{:X}", mod->name, addr - mod->addr);

	return std::format("{}!{}", mod->name, sym->format());
}
