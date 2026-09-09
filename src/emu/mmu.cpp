#include "mmu.hpp"
#include "emu.hpp"

void mmu::read_phys(addr_t pa, void* buf, std::size_t size)
{
	emu_->read_phys_mem(pa, buf, size);
}

void mmu::write_phys(addr_t pa, const void* buf, std::size_t size)
{
	emu_->write_phys_mem(pa, buf, size);
}

addr_t mmu::alloc_phys(std::size_t size, mem_prot prot)
{
	std::lock_guard lk(mtx_);

	const std::size_t aligned = size_align(size);

	const addr_t addr = phys_next_;
	phys_next_ += aligned;

	emu_->map_phys_mem(addr, aligned, prot);

	return addr;
}
