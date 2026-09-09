#include "map.hpp"
#include "../emu/addr_space.hpp"
#include "../process/process.hpp"
#include "../util/log.hpp"

bool krnl::map_img(process& proc, const std::string_view name, const pe::image* const img, const bool supervisor)
{
	auto flags = prot_read;

	if (supervisor)
		flags = flags | prot_supervisor;

	const auto size = img->size();
	const auto space = proc.addr_space();
	const addr_t addr = space->alloc(size, flags);

	if (!addr)
	{
		return false;
	}

	space->write_mem(addr, img->as(), img->size());

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
			return false;
		}

		const auto patch_loc = addr + imp.iat_slot.rva();
		const auto import_addr = mod->find_export(imp.import_name);

		if (!import_addr)
		{
			LOG_ERR("unable to find import {}!{}", imp.module_name, imp.import_name);
			return false;
		}

		space->write_mem(patch_loc, import_addr.value());
	}

	const addr_t delta = addr - img->base_addr();

	for (const auto reloc : img->relocs())
	{
		if (reloc.type != pe::reloc_type::dir64)
			continue;

		const auto reloc_addr = addr + reloc.loc.rva();
		const auto val = space->read_mem<std::uint64_t>(reloc_addr);

		space->write_mem(reloc_addr, val + delta);
	}

	proc.add_module(name, addr, img);

	return true;
}
