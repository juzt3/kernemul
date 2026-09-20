#pragma once
#include <utility>
#include "defs.hpp"
#include "addr_space.hpp"
#include <functional>
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

	void back_phys(addr_t pa, std::size_t size);

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

	// Told about a page as it is mapped or unmapped, and about each table that maps it. An os
	// that keeps a record of physical frames writes it from here: everything such a record can
	// want is already in hand at this moment, so nothing has to be remembered and nothing has to
	// be swept afterwards.
	//
	// `level` is 0 for the page itself and counts up through the tables above it; `table_pa` is
	// the table that level's entry lives in. `va` is the mapped address at every level, so a
	// consumer that wants the entry's own address derives it from `va` and `level`.
	//
	// Called with this mmu's writer lock held. It may use read_phys and write_phys, which take
	// no lock, and nothing else here: the lock is not recursive, so a virtual read or write from
	// inside would deadlock against it.
	using page_note_fn = std::function<void(mmu&, addr_t pa, addr_t va, addr_t table_pa,
		unsigned level, bool mapped)>;

	void set_page_note(page_note_fn fn) { page_note_ = std::move(fn); }

	// The whole of guest physical memory, not the part of it that happens to be backed. A
	// machine's memory map does not grow as its memory manager hands pages out, so a guest that
	// reads this twice and sees a bigger number is reading something no hardware does. Every
	// other answer about physical memory -- MmGetPhysicalMemoryRanges, the basic information
	// block, the length of the pfn database -- is derived from this one so they cannot disagree.
	[[nodiscard]] static constexpr std::pair<addr_t, std::size_t> phys_range() noexcept
	{
		return { phys_base, phys_size };
	}

	// Where guest physical memory starts. The first megabyte of a pc is the real mode vectors,
	// the bios data area, video memory and option roms -- a machine has no usable ram there and
	// never puts page tables or an image in it, so a guest reading a page frame below it is
	// reading something that could not have come from hardware. Above 4gb also puts the frames
	// where a machine with this much memory really does keep them.
	static constexpr addr_t phys_base = 0x100000000;

	// 4gb of it, so the last frame is 0x1FFFFF. The builds this claims to be do not install on
	// less, and the pfn database is as long as the highest frame rather than as long as the
	// count -- so this is what decides that 96mb allocation too.
	static constexpr std::size_t phys_size = 0x100000000;

	// One past the last byte that exists. Allocation stops here rather than running past it.
	static constexpr addr_t phys_end = phys_base + phys_size;

protected:
	void note_page(const addr_t pa, const addr_t va, const addr_t table_pa,
		const unsigned level, const bool mapped)
	{
		if (page_note_)
			page_note_(*this, pa, va, table_pa, level, mapped);
	}

	addr_t alloc_phys_locked(std::size_t size, mem_prot prot);

	addr_t page_align(addr_t addr) const { return addr & ~(page_size() - 1); }
	std::size_t size_align(std::size_t size) const { return (size + page_size() - 1) & ~(page_size() - 1); }

	class emu* emu_ = nullptr;
	page_note_fn page_note_;
	addr_t phys_next_ = phys_base;
	mutable std::shared_mutex mtx_;
};
