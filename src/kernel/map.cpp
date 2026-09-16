#include "map.hpp"
#include "../emu/addr_space.hpp"
#include "../emu/object.hpp"
#include "process.hpp"
#include "../util/log.hpp"
#include "../util/file.hpp"
#include <algorithm>
#include <charconv>
#include <format>
#include <cstring>

namespace {

std::shared_ptr<proc_module> find_or_load(process& proc, const std::string_view name,
	const std::string_view importer, const bool supervisor)
{
	const auto real_name = proc.resolve_module_name(name, importer);

	if (auto mod = proc.find_module(real_name))
		return mod;

	return proc.load_module(real_name, supervisor);
}

std::optional<addr_t> resolve_export(process& proc, const proc_module& mod,
	const std::string_view sym, const bool supervisor, const int depth = 0)
{
	if (const auto addr = mod.find_export(sym))
		return addr;

	const auto forward = mod.find_forward(sym);

	if (forward.empty())
		return std::nullopt;

	if (depth >= 8)
	{
		LOG_ERR("{}!{} forwards in a circle", mod.name, sym);
		return std::nullopt;
	}

	const auto dot = forward.find('.');

	if (dot == std::string_view::npos)
		return std::nullopt;

	const auto target_sym = forward.substr(dot + 1);

	// A forwarder names its target without an extension, and the modules behind a kernel one
	// are a mix of .exe, .sys and .dll -- so an already-loaded module is what names it.
	const auto target_mod = forward.substr(0, dot);

	auto target = proc.find_module_by_stem(target_mod);

	if (!target)
		target = find_or_load(proc, std::string(target_mod) + ".dll", mod.name, supervisor);

	if (!target)
	{
		LOG_ERR("{}!{} forwards to {}, which is not here", mod.name, sym, forward);
		return std::nullopt;
	}

	// "NTDLL.#123" forwards to an ordinal rather than to a name.
	if (target_sym.starts_with('#'))
	{
		std::uint32_t ordinal = 0;
		const auto* const first = target_sym.data() + 1;

		if (std::from_chars(first, target_sym.data() + target_sym.size(), ordinal).ec != std::errc{})
		{
			LOG_ERR("{}!{} forwards to {}, which names no ordinal", mod.name, sym, forward);
			return std::nullopt;
		}

		return target->find_ordinal(ordinal);
	}

	return resolve_export(proc, *target, target_sym, supervisor, depth + 1);
}

} // namespace

std::shared_ptr<proc_module> krnl::map_img(process& proc, const std::string_view name, const pe::image* const img, const bool supervisor, const bool skip_imports)
{
	auto flags = prot_read;

	if (supervisor)
		flags = flags | prot_supervisor;

	const auto size = img->size();
	const auto space = proc.addr_space();
	const addr_t addr = space->alloc(size, flags);

	if (!addr)
	{
		return nullptr;
	}

	space->write_mem(addr, img->as(), size);

	// The export directory is walked constantly by anything resolving a routine by name, so
	// watching it would bury every other access under that traffic. It is the one part of a
	// data section a guest is expected to read.
	const auto& exp_dir = img->nt_hdrs()->optional_hdr.data_dirs.exports;
	const auto exp_begin = exp_dir.used() ? exp_dir.virtual_address : 0u;
	const auto exp_end = exp_dir.used() ? exp_dir.virtual_address + exp_dir.size : 0u;

	for (const auto sec : img->sections())
	{
		auto sec_flags = flags;

		if (sec.characteristics.mem_write)
			sec_flags |= prot_write;
		if (sec.characteristics.mem_execute)
			sec_flags |= prot_exec;

		space->prot_mem(addr + sec.virtual_address, sec.virtual_size, sec_flags);

		// Code is where the guest is meant to be; everything else it touches says something
		// about what it is looking for.
		if (sec.characteristics.mem_execute || !sec.virtual_size)
			continue;

		const auto sec_begin = sec.virtual_address;
		const auto sec_end = sec.virtual_address + sec.virtual_size;
		const auto sec_view = sec.name();
		const std::string sec_name(sec_view.data(), sec_view.size());

		// Subtracting the export directory can leave a piece either side of it.
		const auto watch = [&](const std::uint32_t begin, const std::uint32_t end)
		{
			if (begin < end)
				monitor_range(*space, addr + begin, end - begin,
					std::format("{}{}", name, sec_name));
		};

		if (exp_end <= sec_begin || exp_begin >= sec_end)
		{
			watch(sec_begin, sec_end);
		}
		else
		{
			watch(sec_begin, std::max(sec_begin, exp_begin));
			watch(std::min(sec_end, exp_end), sec_end);
		}
	}

	const addr_t delta = addr - img->base_addr();

	if (const auto* lc = img->load_config(); lc && lc->security_cookie)
	{
		const auto cookie_rva = lc->security_cookie - img->base_addr();
		const auto cookie_val = space->read_mem<std::uint64_t>(addr + cookie_rva);
		space->write_mem(addr + cookie_rva, cookie_val + delta);
	}

	for (const auto reloc : img->relocs())
	{
		if (reloc.type != pe::reloc_type::dir64)
			continue;

		const auto reloc_addr = addr + reloc.loc.rva();
		const auto val = space->read_mem<std::uint64_t>(reloc_addr);

		space->write_mem(reloc_addr, val + delta);
	}

	// Registered before its own imports resolve, or modules that import each other load for ever.
	auto mod = proc.add_module(name, addr, img);

	if (skip_imports)
		return mod;

	for (const auto imp : img->imports())
	{
		auto dep = find_or_load(proc, imp.module_name, name, supervisor);

		if (!dep)
		{
			LOG_ERR("unable to find import module {}", imp.module_name);
			return nullptr;
		}

		const auto import_addr = imp.is_ordinal
			? dep->find_ordinal(imp.ordinal)
			: resolve_export(proc, *dep, imp.import_name, supervisor);

		if (!import_addr)
		{
			if (imp.is_ordinal)
				LOG_ERR("unable to find import {}!#{}", imp.module_name, imp.ordinal);
			else
				LOG_ERR("unable to find import {}!{}", imp.module_name, imp.import_name);

			return nullptr;
		}

		space->write_mem(addr + imp.iat_slot.rva(), import_addr.value());
	}

	return mod;
}

std::vector<std::uint8_t> krnl::pe_virtual_image(const std::span<const std::uint8_t> raw)
{
	if (raw.size() < sizeof(pe::dos_header))
		return {};

	const auto* img = reinterpret_cast<const pe::image*>(raw.data());

	if (!img->dos_hdr()->ok())
		return {};

	const auto* nt = img->nt_hdrs();
	const auto virt_size = nt->optional_hdr.size_of_image;
	const auto hdr_size = nt->optional_hdr.size_of_headers;

	std::vector<std::uint8_t> mapped(virt_size, 0);

	const auto copy_size = std::min<std::size_t>(hdr_size, raw.size());
	std::memcpy(mapped.data(), raw.data(), copy_size);

	for (const auto& sec : img->sections())
	{
		if (!sec.pointer_to_raw_data || !sec.size_of_raw_data)
			continue;

		const auto src_off = sec.pointer_to_raw_data;
		const auto dst_off = sec.virtual_address;
		const auto sz = std::min<std::size_t>(sec.size_of_raw_data, raw.size() - src_off);

		if (src_off < raw.size() && dst_off + sz <= virt_size)
			std::memcpy(mapped.data() + dst_off, raw.data() + src_off, sz);
	}

	return mapped;
}

std::shared_ptr<proc_module> krnl::map_img(process& proc, const std::filesystem::path& path, const bool supervisor, const bool skip_imports)
{
	auto raw = util::read_file(path);

	if (raw.empty())
	{
		LOG_ERR("failed to read file {}", path.string());
		return nullptr;
	}

	return map_img(proc, path.filename().string(), std::span{raw}, supervisor, skip_imports);
}

std::shared_ptr<proc_module> krnl::map_img(process& proc, const std::string_view name, const std::span<const std::uint8_t> raw, const bool supervisor, const bool skip_imports)
{
	auto mapped = krnl::pe_virtual_image(raw);

	if (mapped.empty())
		return nullptr;

	const auto* img = reinterpret_cast<const pe::image*>(mapped.data());

	return map_img(proc, name, img, supervisor, skip_imports);
}
