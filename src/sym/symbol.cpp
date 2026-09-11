#include "symbol.hpp"
#include "../kernel/process.hpp"

#include <algorithm>
#include <format>

void module_symbols::insert(std::string name, const addr_t addr, const std::uint32_t size)
{
	if (name_index.contains(name))
		return;

	name_index[name] = entries.size();
	entries.push_back({ std::move(name), addr, size });
}

void module_symbols::sort()
{
	std::ranges::sort(entries, {}, &symbol_info::addr);
}

std::optional<resolved_symbol> module_symbols::resolve(const addr_t addr) const
{
	if (entries.empty())
		return std::nullopt;

	auto it = std::ranges::upper_bound(entries, addr, {}, &symbol_info::addr);

	if (it == entries.begin())
		return std::nullopt;

	--it;

	const auto offset = static_cast<std::uint32_t>(addr - it->addr);

	if (it->size > 0 && offset >= it->size)
		return std::nullopt;

	return resolved_symbol{ &*it, offset };
}

std::optional<addr_t> module_symbols::lookup(const std::string_view name) const
{
	const auto it = name_index.find(std::string(name));

	if (it == name_index.end())
		return std::nullopt;

	return entries[it->second].addr;
}

void export_symbols::load(proc_module& mod)
{
	for (const auto& [name, addr] : mod.exports)
		mod.symbols.insert(name, addr);

	mod.symbols.sort();
}

std::string symbols::format_addr(const process& proc, const addr_t addr)
{
	const auto mod = proc.find_module_by_addr(addr);

	if (!mod)
		return std::format("0x{:X}", addr);

	const auto sym = mod->symbols.resolve(addr);

	if (!sym)
		return std::format("{}+0x{:X}", mod->name, addr - mod->addr);

	return std::format("{}!{}", mod->name, sym->format());
}
