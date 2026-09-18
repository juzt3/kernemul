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

addr_t addr_space::alloc_phys(addr_t pa, std::size_t size, mem_prot prot)
{
	mmu_->back_phys(pa, size);
	return map_phys(pa, size, prot);
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
	std::unique_lock lk(mtx_);
	return alloc_phys_locked(size, prot);
}

void mmu::back_phys(addr_t pa, std::size_t size)
{
	std::unique_lock lk(mtx_);

	const addr_t start = page_align(pa);
	emu_->map_phys_mem(start, size_align(size + (pa - start)));
}

addr_t mmu::alloc_phys_locked(std::size_t size, mem_prot prot)
{
	const std::size_t aligned = size_align(size);

	const addr_t addr = phys_next_;
	phys_next_ += aligned;

	emu_->map_phys_mem(addr, aligned);

	return addr;
}
