#include "map.hpp"
#include "../emu/addr_space.hpp"
#include "../process/process.hpp"

bool krnl::map_img(process& proc, const pe::image* const img, const bool supervisor)
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

	for (const auto sec : img->sections())
	{
		auto sec_flags = flags;

		if (sec.characteristics.mem_write)
			sec_flags |= prot_write;
		if (sec.characteristics.mem_execute)
			sec_flags |= prot_exec;

		space->prot_mem(addr + sec.virtual_address, sec.virtual_size, sec_flags);
	}

	space->write_mem(addr, img->as(), img->size());

	return true;
}
