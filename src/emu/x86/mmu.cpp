#include "mmu.hpp"
#include "../emu.hpp"
#include <stdexcept>
#include <cstring>

namespace ia32 {
#include <ia32.hpp>
}

namespace x86
{

addr_space& mmu::as_x86(::addr_space& space)
{
	auto* p = dynamic_cast<addr_space*>(&space);
	if (!p) throw std::runtime_error("invalid address space type");
	return *p;
}

const addr_space& mmu::as_x86(const ::addr_space& space)
{
	auto* p = dynamic_cast<const addr_space*>(&space);
	if (!p) throw std::runtime_error("invalid address space type");
	return *p;
}

std::shared_ptr<::addr_space> mmu::create_addr_space()
{
	auto space = std::make_shared<addr_space>();
	space->pml4_pa = alloc_phys(page_size(), prot_rw);
	space->mmu_ = this;
	spaces_[space->pml4_pa] = space;
	return space;
}

void mmu::destroy_addr_space(std::shared_ptr<::addr_space> space)
{
	auto& s = as_x86(*space);
	spaces_.erase(s.pml4_pa);
}

std::shared_ptr<::addr_space> mmu::curr_addr_space(vcpu& cpu)
{
	addr_t cr3 = cpu.reg<addr_t>(x86::cr3);
	auto it = spaces_.find(cr3);
	if (it == spaces_.end())
		return nullptr;
	return it->second;
}

void mmu::init_vcpu(vcpu& cpu)
{
	auto cr4_val = cpu.reg<ia32::cr4>(x86::cr4);
	cr4_val.physical_address_extension = 1;
	cr4_val.os_fxsave_fxrstor_support = 1;
	cr4_val.os_xmm_exception_support = 1;
	cpu.reg(x86::cr4, cr4_val);

	auto efer_val = cpu.reg<ia32::ia32_efer_register>(x86::efer);
	efer_val.syscall_enable = 1;
	efer_val.ia32e_mode_enable = 1;
	efer_val.ia32e_mode_active = 1;
	cpu.reg(x86::efer, efer_val);

	auto cr0_val = cpu.reg<ia32::cr0>(x86::cr0);
	cr0_val.protection_enable = 1;
	cr0_val.monitor_coprocessor = 1;
	cr0_val.numeric_error = 1;
	cr0_val.paging_enable = 1;
	cpu.reg(x86::cr0, cr0_val);
}

void mmu::switch_to(vcpu& cpu, std::shared_ptr<::addr_space> space)
{
	auto& s = as_x86(*space);

	std::lock_guard lk(mtx_);

	cpu.reg(x86::cr3, s.pml4_pa);
	cpu.flush_tlb();
}

void mmu::flush_all_tlb()
{
	for (auto& cpu : emu_->cpus())
		cpu->flush_tlb();
}

addr_t mmu::ensure_table(addr_t table_pa, std::size_t index)
{
	auto entry = read_phys<ia32::pt_entry_64>(table_pa + index * sizeof(ia32::pt_entry_64));

	if (entry.present)
		return pfn_to_pa(entry.page_frame_number);

	addr_t child = alloc_phys(page_size(), prot_rw);
	entry.flags = 0;
	entry.present = 1;
	entry.write = 1;
	entry.supervisor = 1;
	entry.page_frame_number = child >> page_shift;
	write_phys(table_pa + index * sizeof(ia32::pt_entry_64), entry);

	return child;
}

void mmu::map_page(addr_space& space, addr_t va, addr_t pa, bool user)
{
	virt_addr v{ .val = page_align(va) };

	addr_t pdpt = ensure_table(space.pml4_pa, v.pml4);
	addr_t pd   = ensure_table(pdpt, v.pdpt);
	addr_t pt   = ensure_table(pd, v.pd);

	ia32::pte_64 entry{};
	entry.present = 1;
	entry.write = 1;
	if (user)
		entry.supervisor = 1;
	entry.page_frame_number = pa >> page_shift;

	write_phys(pt + v.pt * sizeof(ia32::pte_64), entry);

	space.shadow[v.val] = pa;
}

void mmu::unmap_page(addr_space& space, addr_t va)
{
	virt_addr v{ .val = page_align(va) };

	auto pml4e = read_phys<ia32::pt_entry_64>(space.pml4_pa + v.pml4 * sizeof(ia32::pt_entry_64));
	if (!pml4e.present) return;

	auto pdpte = read_phys<ia32::pt_entry_64>(pfn_to_pa(pml4e.page_frame_number) + v.pdpt * sizeof(ia32::pt_entry_64));
	if (!pdpte.present) return;

	auto pde = read_phys<ia32::pt_entry_64>(pfn_to_pa(pdpte.page_frame_number) + v.pd * sizeof(ia32::pt_entry_64));
	if (!pde.present) return;

	write_phys<std::uint64_t>(pfn_to_pa(pde.page_frame_number) + v.pt * sizeof(ia32::pte_64), 0);

	space.shadow.erase(v.val);
}

void mmu::map_virt(::addr_space& space, addr_t va, std::size_t size, mem_prot prot)
{
	auto& s = as_x86(space);
	std::lock_guard lk(mtx_);

	bool user = !(prot & prot_supervisor);
	auto phys_prot = prot & ~prot_supervisor;

	const addr_t start = page_align(va);
	const std::size_t aligned = size_align(size);

	const addr_t pa_block = alloc_phys(aligned, phys_prot);

	for (std::size_t off = 0; off < aligned; off += page_size())
		map_page(s, start + off, pa_block + off, user);

	flush_all_tlb();
}

void mmu::map_virt_phys(::addr_space& space, addr_t va, addr_t pa, std::size_t size, mem_prot prot)
{
	auto& s = as_x86(space);
	std::lock_guard lk(mtx_);

	const bool user = !(prot & prot_supervisor);
	const addr_t start = page_align(va);
	const addr_t pa_start = page_align(pa);
	const std::size_t aligned = size_align(size);

	for (std::size_t off = 0; off < aligned; off += page_size())
		map_page(s, start + off, pa_start + off, user);

	flush_all_tlb();
}

void mmu::unmap_virt(::addr_space& space, addr_t va, std::size_t size)
{
	auto& s = as_x86(space);
	std::lock_guard lk(mtx_);

	const addr_t start = page_align(va);
	const std::size_t aligned = size_align(size);

	for (std::size_t off = 0; off < aligned; off += page_size())
		unmap_page(s, start + off);

	flush_all_tlb();
}

void mmu::copy_virt(const addr_space& space, addr_t va, void* buf, std::size_t size, bool write)
{
	auto* bytes = static_cast<std::uint8_t*>(buf);
	std::size_t done = 0;

	while (done < size)
	{
		addr_t cur_va = va + done;
		addr_t page = page_align(cur_va);
		std::size_t page_off = cur_va - page;
		std::size_t chunk = std::min(size - done, page_size() - page_off);

		auto it = space.shadow.find(page);
		if (it == space.shadow.end())
			throw std::runtime_error("unmapped virtual address");

		addr_t pa = it->second + page_off;

		if (write)
			write_phys(pa, bytes + done, chunk);
		else
			read_phys(pa, bytes + done, chunk);

		done += chunk;
	}
}

void mmu::read_virt(const ::addr_space& space, addr_t va, void* buf, std::size_t size)
{
	auto& s = as_x86(space);
	std::lock_guard lk(mtx_);
	copy_virt(s, va, buf, size, false);
}

void mmu::write_virt(const ::addr_space& space, addr_t va, const void* buf, std::size_t size)
{
	auto& s = as_x86(space);
	std::lock_guard lk(mtx_);
	copy_virt(s, va, const_cast<void*>(buf), size, true);
}

void mmu::prot_virt(::addr_space& space, addr_t va, std::size_t size, mem_prot prot)
{
	auto& s = as_x86(space);
	std::lock_guard lk(mtx_);

	const addr_t start = page_align(va);
	const std::size_t aligned = size_align(size);

	for (std::size_t off = 0; off < aligned; off += page_size())
	{
		virt_addr v{ .val = start + off };

		auto pml4e = read_phys<ia32::pt_entry_64>(s.pml4_pa + v.pml4 * sizeof(ia32::pt_entry_64));
		if (!pml4e.present) continue;

		auto pdpte = read_phys<ia32::pt_entry_64>(pfn_to_pa(pml4e.page_frame_number) + v.pdpt * sizeof(ia32::pt_entry_64));
		if (!pdpte.present) continue;

		auto pde = read_phys<ia32::pt_entry_64>(pfn_to_pa(pdpte.page_frame_number) + v.pd * sizeof(ia32::pt_entry_64));
		if (!pde.present) continue;

		addr_t pt_pa = pfn_to_pa(pde.page_frame_number);
		auto pte = read_phys<ia32::pte_64>(pt_pa + v.pt * sizeof(ia32::pte_64));
		if (!pte.present) continue;

		ia32::pte_64 new_pte{};
		new_pte.present = 1;
		new_pte.page_frame_number = pte.page_frame_number;
		if (prot & prot_write)
			new_pte.write = 1;
		if (pte.supervisor)
			new_pte.supervisor = 1;

		write_phys(pt_pa + v.pt * sizeof(ia32::pte_64), new_pte);
	}

	flush_all_tlb();
}

std::optional<addr_t> mmu::virt_to_phys(const ::addr_space& space, addr_t va)
{
	auto& s = as_x86(space);
	std::lock_guard lk(mtx_);

	addr_t page = page_align(va);
	auto it = s.shadow.find(page);
	if (it == s.shadow.end())
		return std::nullopt;

	return it->second + (va - page);
}

std::optional<addr_t> mmu::phys_to_virt(const ::addr_space& space, addr_t pa)
{
	auto& s = as_x86(space);
	std::lock_guard lk(mtx_);

	addr_t pa_page = pa & ~(page_size() - 1);
	addr_t offset = pa - pa_page;

	for (auto& [va_page, mapped_pa] : s.shadow)
	{
		if (mapped_pa == pa_page)
			return va_page + offset;
	}

	return std::nullopt;
}

addr_t addr_space::alloc(std::size_t size, mem_prot prot)
{
	constexpr std::size_t page = 0x1000;
	auto aligned = (size + page - 1) & ~(page - 1);

	addr_t& cursor = (prot & prot_supervisor) ? kernel_next_ : user_next_;
	addr_t va = cursor;
	cursor += aligned;

	mmu_->map_virt(*this, va, aligned, prot);
	return va;
}

}
