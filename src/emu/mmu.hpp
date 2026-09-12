#pragma once
#include "defs.hpp"
#include "addr_space.hpp"
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <optional>

class emu;
class vcpu;

class mmu
{
public:
	mmu() = default;
	virtual ~mmu() = default;

	virtual void map_virt(addr_space& space, addr_t va, std::size_t size, mem_prot prot) = 0;
	virtual void map_virt_phys(addr_space& space, addr_t va, addr_t pa, std::size_t size, mem_prot prot) = 0;
	virtual void unmap_virt(addr_space& space, addr_t va, std::size_t size) = 0;
	virtual void read_virt(const addr_space& space, addr_t va, void* buf, std::size_t size) = 0;
	virtual void write_virt(const addr_space& space, addr_t va, const void* buf, std::size_t size) = 0;
	virtual void prot_virt(addr_space& space, addr_t va, std::size_t size, mem_prot prot) = 0;

	void read_phys(addr_t pa, void* buf, std::size_t size);
	void write_phys(addr_t pa, const void* buf, std::size_t size);

	template <typename T>
	T read_phys(addr_t pa)
	{
		T val{};
		read_phys(pa, &val, sizeof(T));
		return val;
	}

	template <typename T>
	void write_phys(addr_t pa, const T& val)
	{
		write_phys(pa, &val, sizeof(T));
	}

	addr_t alloc_phys(std::size_t size, mem_prot prot);

	virtual std::size_t page_size() const = 0;

	virtual std::optional<addr_t> virt_to_phys(const addr_space& space, addr_t va) = 0;
	virtual std::optional<addr_t> phys_to_virt(const addr_space& space, addr_t pa) = 0;

	virtual std::shared_ptr<addr_space> create_addr_space() = 0;
	virtual void destroy_addr_space(std::shared_ptr<addr_space> space) = 0;
	virtual std::shared_ptr<addr_space> curr_addr_space(vcpu& cpu) = 0;
	virtual void init_vcpu(vcpu& cpu) = 0;
	virtual void switch_to(vcpu& cpu, std::shared_ptr<addr_space> space) = 0;

	void set_emu(emu* backend) { emu_ = backend; }
	[[nodiscard]] class emu* emu() const noexcept { return emu_; }

protected:
	// The same, for callers that already hold mtx_ -- the table walkers do,
	// and they allocate the tables they are missing as they go.
	addr_t alloc_phys_locked(std::size_t size, mem_prot prot);

	addr_t page_align(addr_t addr) const { return addr & ~(page_size() - 1); }
	std::size_t size_align(std::size_t size) const { return (size + page_size() - 1) & ~(page_size() - 1); }

	class emu* emu_ = nullptr;
	addr_t phys_next_ = 0x10000;
	// Walks read the tables, mapping rewrites them. Reads are by far the more
	// common: every guest memory access from the host side is one.
	mutable std::shared_mutex mtx_;
};
