#include "map.hpp"
#include "../emu/addr_space.hpp"
#include "process.hpp"
#include "../util/log.hpp"
#include "../util/file.hpp"

std::shared_ptr<proc_module> krnl::map_img(process& proc, const std::string_view name, const pe::image* const img, const bool supervisor)
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

	for (const auto sec : img->sections())
	{
		auto sec_flags = flags;

		if (sec.characteristics.mem_write)
			sec_flags |= prot_write;
		if (sec.characteristics.mem_execute)
			sec_flags |= prot_exec;

		space->prot_mem(addr + sec.virtual_address, sec.virtual_size, sec_flags);
	}

	for (const auto imp : img->imports())
	{
		const auto mod = proc.find_module(imp.module_name);

		if (!mod)
		{
			LOG_ERR("unable to find import module {}", imp.module_name);
			return nullptr;
		}

		const auto patch_loc = addr + imp.iat_slot.rva();
		const auto import_addr = mod->find_export(imp.import_name);

		if (!import_addr)
		{
			LOG_ERR("unable to find import {}!{}", imp.module_name, imp.import_name);
			return nullptr;
		}

		space->write_mem(patch_loc, import_addr.value());
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

	return proc.add_module(name, addr, img);
}

static std::vector<std::uint8_t> map_pe_virtual(const std::vector<std::uint8_t>& raw)
{
	const auto* img = reinterpret_cast<const pe::image*>(raw.data());
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

std::shared_ptr<proc_module> krnl::map_img(process& proc, const std::filesystem::path& path, const bool supervisor)
{
	auto raw = util::read_file(path);

	if (raw.empty())
	{
		LOG_ERR("failed to read file {}", path.string());
		return nullptr;
	}

	auto mapped = map_pe_virtual(raw);
	const auto* img = reinterpret_cast<const pe::image*>(mapped.data());
	const auto name = path.filename().string();

	return map_img(proc, name, img, supervisor);
}
