#pragma once
#include "defs.hpp"
#include <cstddef>

class mmu;

struct addr_space
{
	virtual ~addr_space() = default;
	virtual addr_t alloc(std::size_t size, mem_prot prot) = 0;

	// A window onto physical memory that already exists, rather than a fresh
	// allocation: the caller says which physical page it wants and gets a
	// virtual address pointing at it. Both `pa` and `size` are page aligned by
	// the caller. This is what MmMapIoSpace is for.
	virtual addr_t map_phys(addr_t pa, std::size_t size, mem_prot prot) = 0;

	void read_mem(addr_t va, void* buf, std::size_t size);
	void write_mem(addr_t va, const void* buf, std::size_t size);
	void prot_mem(addr_t va, std::size_t size, mem_prot prot);

	template <typename T>
	T read_mem(addr_t va)
	{
		T val{};
		read_mem(va, &val, sizeof(T));
		return val;
	}

	template <typename T>
	void write_mem(addr_t va, const T& val)
	{
		write_mem(va, &val, sizeof(T));
	}

	mmu* mmu_ = nullptr;
};
