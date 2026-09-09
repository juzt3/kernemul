#include "mmu.hpp"
#include "emu.hpp"

void addr_space::read_mem(addr_t va, void* buf, std::size_t size)
{
	mmu_->read_virt(*this, va, buf, size);
}

void addr_space::write_mem(addr_t va, const void* buf, std::size_t size)
{
	mmu_->write_virt(*this, va, buf, size);
}

void addr_space::prot_mem(addr_t va, std::size_t size, mem_prot prot)
{
	mmu_->prot_virt(*this, va, size, prot);
}

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
