#include "mmu.hpp"
#include "arch.hpp"
#include "../emu.hpp"
#include <stdexcept>
#include <cstring>

namespace arm64
{

addr_space& mmu::as_arm64(::addr_space& space)
{
	auto* p = dynamic_cast<addr_space*>(&space);
	if (!p) throw std::runtime_error("invalid address space type");
	return *p;
}

const addr_space& mmu::as_arm64(const ::addr_space& space)
{
	auto* p = dynamic_cast<const addr_space*>(&space);
	if (!p) throw std::runtime_error("invalid address space type");
	return *p;
}

std::shared_ptr<::addr_space> mmu::create_addr_space()
{
	std::unique_lock lk(mtx_);

	auto space = std::make_shared<addr_space>();
	space->ttbr_pa = alloc_phys_locked(page_size(), prot_rw);
	space->mmu_ = this;

	if (!kernel_ttbr_pa_)
	{
		kernel_ttbr_pa_ = space->ttbr_pa;
	}
	else
	{
		const std::size_t entries = page_size() / sizeof(std::uint64_t);

		for (std::size_t i = entries / 2; i < entries; ++i)
		{
			const auto off = i * sizeof(std::uint64_t);
			write_phys<std::uint64_t>(space->ttbr_pa + off,
				read_phys<std::uint64_t>(kernel_ttbr_pa_ + off));
		}
	}

	spaces_[space->ttbr_pa] = space;
	return space;
}

void mmu::destroy_addr_space(std::shared_ptr<::addr_space> space)
{
	std::unique_lock lk(mtx_);

	auto& s = as_arm64(*space);
	spaces_.erase(s.ttbr_pa);
}

std::shared_ptr<::addr_space> mmu::curr_addr_space(vcpu& cpu)
{
	const addr_t ttbr = cpu.reg<addr_t>(ttbr0_el1) & desc_addr_mask;

	std::shared_lock lk(mtx_);
	auto it = spaces_.find(ttbr);
	if (it == spaces_.end())
		return nullptr;
	return it->second;
}

void mmu::init_vcpu(vcpu& cpu)
{
	// Attr0: normal memory, write-back non-transient RW-allocate; every page uses AttrIndx = 0.
	cpu.reg(mair_el1, std::uint64_t{0xFF});

	// T0SZ=16 IRGN0=1 ORGN0=1 SH0=3 TG0=0 (4KB)
	// T1SZ=16 IRGN1=1 ORGN1=1 SH1=3 TG1=2 (4KB)   IPS=2 (40-bit)
	constexpr std::uint64_t t0sz = 16, t1sz = 16;
	const std::uint64_t tcr =
		  (t0sz <<  0) | (1ull <<  8) | (1ull << 10) | (3ull << 12) | (0ull << 14)
		| (t1sz << 16) | (1ull << 24) | (1ull << 26) | (3ull << 28) | (2ull << 30)
		| (2ull << 32);
	cpu.reg(tcr_el1, tcr);

	// Read-modify-write so the RES1 bits Unicorn already set survive.
	auto sctlr = cpu.reg<std::uint64_t>(sctlr_el1);
	sctlr |= (1ull << 0)   // M: enable stage 1 translation
	      |  (1ull << 2)   // C: data accesses cacheable
	      |  (1ull << 12); // I: instruction accesses cacheable
	cpu.reg(sctlr_el1, sctlr);
}

void mmu::switch_to(vcpu& cpu, std::shared_ptr<::addr_space> space)
{
	auto& s = as_arm64(*space);

	std::shared_lock lk(mtx_);

	cpu.reg(ttbr0_el1, s.ttbr_pa);
	cpu.reg(ttbr1_el1, s.ttbr_pa);
	cpu.flush_tlb();
}

void mmu::flush_all_tlb()
{
	// uc_ctl_flush_tlb rewrites the tlb, so flushing a running cpu corrupts it under the cpu.
	emu_->run_on_all([&]
	{
		for (auto& cpu : emu_->cpus())
			cpu->flush_tlb();
	});
}

std::uint64_t mmu::page_attrs(const mem_prot prot)
{
	std::uint64_t attrs = desc_valid | desc_table | desc_af | desc_sh_is;

	if (!(prot & prot_supervisor))
		attrs |= desc_ap_el0;

	if (!(prot & prot_write))
		attrs |= desc_ap_ro;

	// Execution stays enabled at both levels: PXN would fault the driver on its own code.
	return attrs;
}

addr_t mmu::ensure_table(const addr_t table_pa, const std::size_t index)
{
	const auto entry = read_phys<std::uint64_t>(table_pa + index * sizeof(std::uint64_t));

	if (entry & desc_valid)
		return entry & desc_addr_mask;

	const addr_t child = alloc_phys_locked(page_size(), prot_rw);

	write_phys<std::uint64_t>(table_pa + index * sizeof(std::uint64_t),
		(child & desc_addr_mask) | desc_valid | desc_table);

	return child;
}

void mmu::map_page(addr_space& space, const addr_t va, const addr_t pa, const mem_prot prot)
{
	const virt_addr v{ .val = page_align(va) };

	const addr_t l1 = ensure_table(space.ttbr_pa, v.l0);
	const addr_t l2 = ensure_table(l1, v.l1);
	const addr_t l3 = ensure_table(l2, v.l2);

	write_phys<std::uint64_t>(l3 + v.l3 * sizeof(std::uint64_t),
		(pa & desc_addr_mask) | page_attrs(prot));

	space.shadow[v.val] = pa;
}

addr_t mmu::walk_to_l3(const addr_space& space, const addr_t va)
{
	const virt_addr v{ .val = page_align(va) };

	auto step = [this](const addr_t table, const std::size_t idx) -> addr_t
	{
		const auto e = read_phys<std::uint64_t>(table + idx * sizeof(std::uint64_t));
		return (e & desc_valid) ? (e & desc_addr_mask) : 0;
	};

	const addr_t l1 = step(space.ttbr_pa, v.l0);
	if (!l1) return 0;
	const addr_t l2 = step(l1, v.l1);
	if (!l2) return 0;
	return step(l2, v.l2);
}

std::optional<addr_t> mmu::translate_virt(const addr_space& space, const addr_t page)
{
	const addr_t l3 = walk_to_l3(space, page);

	if (!l3)
		return std::nullopt;

	const virt_addr v{ .val = page };
	const auto entry = read_phys<std::uint64_t>(l3 + v.l3 * sizeof(std::uint64_t));

	if (!(entry & desc_valid))
		return std::nullopt;

	return entry & desc_addr_mask;
}

void mmu::unmap_page(addr_space& space, const addr_t va)
{
	const virt_addr v{ .val = page_align(va) };

	if (const addr_t l3 = walk_to_l3(space, va))
		write_phys<std::uint64_t>(l3 + v.l3 * sizeof(std::uint64_t), 0);

	space.shadow.erase(v.val);
}

void mmu::map_virt(::addr_space& space, const addr_t va, const std::size_t size, const mem_prot prot)
{
	auto& s = as_arm64(space);
	std::unique_lock lk(mtx_);

	const auto phys_prot = prot & ~prot_supervisor;

	const addr_t start = page_align(va);
	const std::size_t aligned = size_align(size);

	const addr_t pa_block = alloc_phys_locked(aligned, phys_prot);

	// Mapped writable and narrowed later by prot_virt, since krnl::map_img writes the image first.
	for (std::size_t off = 0; off < aligned; off += page_size())
		map_page(s, start + off, pa_block + off, prot | prot_write);

	flush_all_tlb();
}

void mmu::map_virt_phys(::addr_space& space, const addr_t va, const addr_t pa, const std::size_t size, const mem_prot prot)
{
	auto& s = as_arm64(space);
	std::unique_lock lk(mtx_);

	const addr_t start = page_align(va);
	const addr_t pa_start = page_align(pa);
	const std::size_t aligned = size_align(size);

	for (std::size_t off = 0; off < aligned; off += page_size())
		map_page(s, start + off, pa_start + off, prot | prot_write);

	flush_all_tlb();
}

void mmu::unmap_virt(::addr_space& space, const addr_t va, const std::size_t size)
{
	auto& s = as_arm64(space);
	std::unique_lock lk(mtx_);

	const addr_t start = page_align(va);
	const std::size_t aligned = size_align(size);

	for (std::size_t off = 0; off < aligned; off += page_size())
		unmap_page(s, start + off);

	flush_all_tlb();
}

void mmu::copy_virt(const addr_space& space, const addr_t va, void* buf, const std::size_t size, const bool write)
{
	auto* bytes = static_cast<std::uint8_t*>(buf);
	std::size_t done = 0;

	while (done < size)
	{
		const addr_t cur_va = va + done;
		const addr_t page = page_align(cur_va);
		const std::size_t page_off = cur_va - page;
		const std::size_t chunk = std::min(size - done, page_size() - page_off);

		const auto it = space.shadow.find(page);

		const auto frame = it != space.shadow.end()
			? std::optional<addr_t>(it->second)
			: translate_virt(space, page);

		if (!frame)
			throw std::runtime_error("unmapped virtual address");

		const addr_t pa = *frame + page_off;

		if (write)
			write_phys(pa, bytes + done, chunk);
		else
			read_phys(pa, bytes + done, chunk);

		done += chunk;
	}
}

void mmu::read_virt(const ::addr_space& space, const addr_t va, void* buf, const std::size_t size)
{
	auto& s = as_arm64(space);
	std::shared_lock lk(mtx_);
	copy_virt(s, va, buf, size, false);
}

void mmu::write_virt(const ::addr_space& space, const addr_t va, const void* buf, const std::size_t size)
{
	auto& s = as_arm64(space);
	std::shared_lock lk(mtx_);
	copy_virt(s, va, const_cast<void*>(buf), size, true);
}

void mmu::prot_virt(::addr_space& space, const addr_t va, const std::size_t size, const mem_prot prot)
{
	auto& s = as_arm64(space);
	std::unique_lock lk(mtx_);

	const addr_t start = page_align(va);
	const std::size_t aligned = size_align(size);

	for (std::size_t off = 0; off < aligned; off += page_size())
	{
		const virt_addr v{ .val = start + off };

		const addr_t l3 = walk_to_l3(s, v.val);
		if (!l3) continue;

		const auto slot = l3 + v.l3 * sizeof(std::uint64_t);
		const auto entry = read_phys<std::uint64_t>(slot);
		if (!(entry & desc_valid)) continue;

		auto attrs = page_attrs(prot);
		attrs &= ~desc_ap_el0;
		attrs |= entry & desc_ap_el0;

		write_phys<std::uint64_t>(slot, (entry & desc_addr_mask) | attrs);
	}

	flush_all_tlb();
}

std::optional<addr_t> mmu::virt_to_phys(const ::addr_space& space, const addr_t va)
{
	auto& s = as_arm64(space);
	std::shared_lock lk(mtx_);

	const addr_t page = page_align(va);
	const auto it = s.shadow.find(page);

	if (it != s.shadow.end())
		return it->second + (va - page);

	if (const auto pa = translate_virt(s, page))
		return *pa + (va - page);

	return std::nullopt;
}

std::optional<addr_t> mmu::phys_to_virt(const ::addr_space& space, const addr_t pa)
{
	auto& s = as_arm64(space);
	std::shared_lock lk(mtx_);

	const addr_t pa_page = pa & ~(page_size() - 1);
	const addr_t offset = pa - pa_page;

	for (auto& [va_page, mapped_pa] : s.shadow)
	{
		if (mapped_pa == pa_page)
			return va_page + offset;
	}

	return std::nullopt;
}

addr_t addr_space::alloc(const std::size_t size, const mem_prot prot)
{
	constexpr std::size_t page = 0x1000;
	const auto aligned = (size + page - 1) & ~(page - 1);

	addr_t& cursor = (prot & prot_supervisor) ? kernel_next_ : user_next_;
	const addr_t va = cursor;
	cursor += aligned;

	mmu_->map_virt(*this, va, aligned, prot);
	return va;
}

addr_t addr_space::map_phys(const addr_t pa, const std::size_t size, const mem_prot prot)
{
	constexpr std::size_t page = 0x1000;
	const auto aligned = (size + page - 1) & ~(page - 1);

	addr_t& cursor = (prot & prot_supervisor) ? kernel_next_ : user_next_;
	const addr_t va = cursor;
	cursor += aligned;

	mmu_->map_virt_phys(*this, va, pa, aligned, prot);
	return va;
}

}
