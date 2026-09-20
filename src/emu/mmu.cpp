#include "mmu.hpp"
#include "emu.hpp"
#include <format>
#include <stdexcept>

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

	// A frame past the end is one the guest was never told it has: nothing in the pfn database
	// describes it and MmGetPhysicalMemoryRanges does not cover it, so handing it out makes the
	// emulator's own account of its memory false. Written as a subtraction from the end so the
	// sum cannot wrap. Failing here is louder than the alternative, which is a driver reading a
	// frame number the machine says does not exist.
	if (aligned > phys_end - addr)
		throw std::runtime_error(std::format(
			"out of guest physical memory: 0x{:X} more bytes at 0x{:X}, which ends at 0x{:X}",
			aligned, addr, phys_end));

	phys_next_ += aligned;

	emu_->map_phys_mem(addr, aligned);

	return addr;
}
