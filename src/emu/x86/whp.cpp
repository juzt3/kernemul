#include "whp.hpp"

#if defined(KERNEMUL_HAS_WHP)
#include "../mmu.hpp"
#include "../calling_conv.hpp"

#include <emulator/emulator.hpp>

#include <algorithm>
#include <cstring>
#include <format>
#include <optional>
#include <stdexcept>

namespace
{

constexpr std::size_t page_size = hm::emu::page_size;

addr_t page_align(const addr_t addr)
{
	return addr & ~static_cast<addr_t>(page_size - 1);
}

bool is_seg_reg(const reg_t reg)
{
	return reg >= x86::cs && reg <= x86::ldtr;
}

bool is_table_reg(const reg_t reg)
{
	return reg == x86::gdtr || reg == x86::idtr;
}

bool is_xmm_reg(const reg_t reg)
{
	return reg >= x86::xmm0 && reg <= x86::xmm15;
}

hm::reg_t to_hm_reg(const reg_t reg)
{
	switch (reg)
	{
	case x86::rax:    return hm::reg::rax;
	case x86::rcx:    return hm::reg::rcx;
	case x86::rdx:    return hm::reg::rdx;
	case x86::rbx:    return hm::reg::rbx;
	case x86::rsp:    return hm::reg::rsp;
	case x86::rbp:    return hm::reg::rbp;
	case x86::rsi:    return hm::reg::rsi;
	case x86::rdi:    return hm::reg::rdi;
	case x86::r8:     return hm::reg::r8;
	case x86::r9:     return hm::reg::r9;
	case x86::r10:    return hm::reg::r10;
	case x86::r11:    return hm::reg::r11;
	case x86::r12:    return hm::reg::r12;
	case x86::r13:    return hm::reg::r13;
	case x86::r14:    return hm::reg::r14;
	case x86::r15:    return hm::reg::r15;
	case x86::rip:    return hm::reg::rip;
	case x86::rflags: return hm::reg::rflags;
	case x86::cr0:    return hm::reg::cr0;
	case x86::cr2:    return hm::reg::cr2;
	case x86::cr3:    return hm::reg::cr3;
	case x86::cr4:    return hm::reg::cr4;
	case x86::cr8:    return hm::reg::cr8;
	case x86::efer:   return hm::reg::efer;
	case x86::star:   return hm::reg::star;
	case x86::lstar:  return hm::reg::lstar;
	case x86::cstar:  return hm::reg::cstar;
	case x86::fmask:  return hm::reg::sfmask;
	case x86::cs:     return hm::reg::cs;
	case x86::ds:     return hm::reg::ds;
	case x86::es:     return hm::reg::es;
	case x86::ss:     return hm::reg::ss;
	case x86::fs:     return hm::reg::fs;
	case x86::gs:     return hm::reg::gs;
	case x86::tr:     return hm::reg::tr;
	case x86::ldtr:   return hm::reg::ldtr;
	case x86::gdtr:   return hm::reg::gdtr;
	case x86::idtr:   return hm::reg::idtr;
	case x86::xmm0:   return hm::reg::xmm0;
	case x86::xmm1:   return hm::reg::xmm1;
	case x86::xmm2:   return hm::reg::xmm2;
	case x86::xmm3:   return hm::reg::xmm3;
	case x86::xmm4:   return hm::reg::xmm4;
	case x86::xmm5:   return hm::reg::xmm5;
	case x86::xmm6:   return hm::reg::xmm6;
	case x86::xmm7:   return hm::reg::xmm7;
	case x86::xmm8:   return hm::reg::xmm8;
	case x86::xmm9:   return hm::reg::xmm9;
	case x86::xmm10:  return hm::reg::xmm10;
	case x86::xmm11:  return hm::reg::xmm11;
	case x86::xmm12:  return hm::reg::xmm12;
	case x86::xmm13:  return hm::reg::xmm13;
	case x86::xmm14:  return hm::reg::xmm14;
	case x86::xmm15:  return hm::reg::xmm15;
	default:
		throw std::runtime_error(std::format("no hypermulator register for {}", reg));
	}
}

// Segment attributes reach the emulator in the descriptor's own layout, where
// the type field starts at bit 8 -- the shape Unicorn's uc_x86_mmr takes. The
// partition wants the compact form the VMCS uses. Bits 19:16 of the descriptor
// form are the high limit nibble and have no place in the compact one.
constexpr std::uint16_t to_hm_seg_attr(const std::uint32_t flags)
{
	return static_cast<std::uint16_t>((flags >> 8) & 0xF0FF);
}

constexpr std::uint32_t from_hm_seg_attr(const std::uint16_t attributes)
{
	return static_cast<std::uint32_t>(attributes & 0xF0FF) << 8;
}

// The supervisor bit lives in the guest page tables, which the mmu writes
// itself. What reaches the partition is the physical page's own protection.
hm::mem_prot to_hm_prot(const mem_prot prot)
{
	return static_cast<hm::mem_prot>(prot & prot_rwx);
}

mem_prot to_prot(const hm::mem_vmexit::access access)
{
	switch (access)
	{
	case hm::mem_vmexit::access::read:    return prot_read;
	case hm::mem_vmexit::access::write:   return prot_write;
	case hm::mem_vmexit::access::execute: return prot_exec;
	default:                              return prot_none;
	}
}

hm::hook_insn_t to_hm_insn(const hook_insn_t insn)
{
	switch (insn)
	{
	case hook_insn_t::cpuid: return hm::hook_insn_t::cpuid;
	case hook_insn_t::rdtsc: return hm::hook_insn_t::rdtsc;
	default:
		// A syscall exit is not one the partition offers.
		throw std::runtime_error("instruction hook unsupported by the hypermulator backend");
	}
}

}

// One virtual hook is any number of native ones, and they go together: the
// emulator removes hooks by the handle it was given.
struct x86_whp_emu::whp_hook : emu_hook
{
	hm::emu* backend = nullptr;
	std::vector<std::shared_ptr<hm::emu_hook>> native;

	~whp_hook() override
	{
		for (const auto& hook : native)
			backend->remove_hook(hook);
	}
};

x86_whp_vcpu::x86_whp_vcpu(x86_whp_emu* const emu, std::shared_ptr<const struct arch> arch,
	hm::emu& backend, const std::size_t id)
	:	vcpu(emu, std::move(arch), id), hm_(backend) { }

void x86_whp_vcpu::run()
{
	hm_.run();
}

void x86_whp_vcpu::stop()
{
	hm_.stop();
}

void x86_whp_vcpu::try_stop()
{
	hm_.try_stop();
}

void x86_whp_vcpu::flush_tlb()
{
	// The partition has no flush of its own for the guest's paging. Reloading
	// cr3 is the architectural one, and a register write is a load as far as
	// the processor is concerned.
	reg(x86::cr3, reg<addr_t>(x86::cr3));
}

void x86_whp_vcpu::reg_read(const reg_t reg, void* const value, const std::size_t size)
{
	const auto native = to_hm_reg(reg);

	const auto read = [&](void* const buf, const std::size_t buf_size)
	{
		if (!hm_.reg_read(native, buf, buf_size))
			throw std::runtime_error(std::format("failed to read register {}", reg));
	};

	if (is_table_reg(reg))
	{
		hm::table_reg table{};
		read(&table, sizeof(table));

		const x86::seg_reg sr{ 0, table.base, table.limit, 0 };
		std::memcpy(value, &sr, std::min(size, sizeof(sr)));
		return;
	}

	if (is_seg_reg(reg))
	{
		hm::segment_reg segment{};
		read(&segment, sizeof(segment));

		const x86::seg_reg sr{
			segment.selector, segment.base, segment.limit, from_hm_seg_attr(segment.attributes)
		};
		std::memcpy(value, &sr, std::min(size, sizeof(sr)));
		return;
	}

	if (is_xmm_reg(reg))
	{
		x86::xmm_t xmm{};
		read(&xmm, sizeof(xmm));

		std::memcpy(value, &xmm, std::min(size, sizeof(xmm)));
		return;
	}

	std::uint64_t raw{};
	read(&raw, sizeof(raw));

	std::memcpy(value, &raw, std::min(size, sizeof(raw)));
}

void x86_whp_vcpu::reg_write(const reg_t reg, const void* const value, const std::size_t size)
{
	const auto native = to_hm_reg(reg);

	const auto write = [&](const void* const buf, const std::size_t buf_size)
	{
		if (!hm_.reg_write(native, buf, buf_size))
			throw std::runtime_error(std::format("failed to write register {}", reg));
	};

	if (is_table_reg(reg) || is_seg_reg(reg))
	{
		x86::seg_reg sr{};
		std::memcpy(&sr, value, std::min(size, sizeof(sr)));

		if (is_table_reg(reg))
		{
			const hm::table_reg table{ {}, static_cast<std::uint16_t>(sr.limit), sr.base };
			write(&table, sizeof(table));
			return;
		}

		const hm::segment_reg segment{
			sr.base, sr.limit, sr.selector, to_hm_seg_attr(sr.flags)
		};
		write(&segment, sizeof(segment));
		return;
	}

	if (is_xmm_reg(reg))
	{
		x86::xmm_t xmm{};
		std::memcpy(&xmm, value, std::min(size, sizeof(xmm)));

		write(&xmm, sizeof(xmm));
		return;
	}

	std::uint64_t raw{};
	std::memcpy(&raw, value, std::min(size, sizeof(raw)));

	write(&raw, sizeof(raw));
}

x86_whp_emu::x86_whp_emu(std::shared_ptr<mmu> mem, std::shared_ptr<calling_conv> call_conv)
	:	emu(std::make_shared<x86::arch>(), std::move(mem), std::move(call_conv)),
		hm_(std::make_unique<hm::emu>(hm::machine_mode_64)) { }

x86_whp_emu::~x86_whp_emu() = default;

std::shared_ptr<vcpu> x86_whp_emu::create_vcpu(const std::size_t id)
{
	if (id != 0)
		throw std::runtime_error("the hypermulator backend runs a single cpu");

	return std::make_shared<x86_whp_vcpu>(this, arch_, *hm_, id);
}

vcpu* x86_whp_emu::hook_cpu() const
{
	return cpus_.empty() ? nullptr : cpus_.front().get();
}

std::vector<x86_whp_emu::phys_run> x86_whp_emu::phys_runs(const addr_t start_addr,
	const addr_t end_addr)
{
	if (start_addr > end_addr)
		throw std::runtime_error("the whp backend needs a bounded hook range");

	// The space the range is meant to be in: the one the cpu is running in, or
	// the kernel's, which is where a hook installed while the machine is still
	// being built belongs.
	const auto cpu = hook_cpu();
	const auto current = cpu ? cpu->curr_addr_space() : nullptr;
	const auto fallback = default_addr_space();

	std::vector<phys_run> runs;

	for (addr_t va = start_addr; va <= end_addr;)
	{
		const addr_t page = page_align(va);
		const addr_t chunk_end = std::min(page + page_size, end_addr + 1);

		auto page_pa = current ? mem_->virt_to_phys(*current, page) : std::nullopt;

		if (!page_pa && current != fallback)
			page_pa = mem_->virt_to_phys(*fallback, page);

		if (!page_pa)
			throw std::runtime_error(std::format("hook range 0x{:X} is not mapped", va));

		const addr_t begin = *page_pa + (va - page);
		const addr_t end = begin + (chunk_end - va);

		if (!runs.empty() && runs.back().end == begin)
			runs.back().end = end;
		else
			runs.push_back({ begin, end });

		va = chunk_end;
	}

	return runs;
}

emu::hook_handle x86_whp_emu::add_hook(std::unique_ptr<whp_hook> hook)
{
	if (std::ranges::find(hook->native, nullptr) != hook->native.end())
		throw std::runtime_error("the partition refused a hook");

	auto* const handle = hook.get();
	hooks_.push_back(std::move(hook));

	return handle;
}

emu::hook_handle x86_whp_emu::hook_mem(const addr_t start_addr, const addr_t end_addr,
	const mem_prot prot, mem_hk_cb cb)
{
	auto hook = std::make_unique<whp_hook>();
	hook->cb = std::move(cb);
	hook->owner = this;
	hook->start = start_addr;
	hook->end = end_addr;
	hook->backend = hm_.get();

	auto& callback = std::get<mem_hk_cb>(hook->cb);

	for (const auto& [begin, end] : phys_runs(start_addr, end_addr))
	{
		hook->native.push_back(hm_->hook_mem(to_hm_prot(prot),
			[this, &callback](const hm::addr_t addr, const hm::mem_vmexit::access access)
			{
				// hypermulator reports the address it resolved the access to
				// and not its width, which no caller of this asks for.
				callback(*hook_cpu(), addr, 0, to_prot(access));
			},
			begin, end));
	}

	return add_hook(std::move(hook));
}

emu::hook_handle x86_whp_emu::hook_insn(const addr_t start_addr, const addr_t end_addr,
	const hook_insn_t insn, insn_hk_cb cb)
{
	auto hook = std::make_unique<whp_hook>();
	hook->cb = std::move(cb);
	hook->owner = this;
	hook->start = start_addr;
	hook->end = end_addr;
	hook->backend = hm_.get();

	auto& callback = std::get<insn_hk_cb>(hook->cb);

	// Instruction exits carry the virtual rip, so this range is not translated.
	const bool bounded = start_addr <= end_addr;

	hook->native.push_back(hm_->hook_insn(to_hm_insn(insn),
		[this, &callback] { return callback(*hook_cpu()); },
		bounded ? start_addr : 0,
		bounded ? end_addr + 1 : 0));

	return add_hook(std::move(hook));
}

emu::hook_handle x86_whp_emu::hook_code(const addr_t start_addr, const addr_t end_addr,
	code_hk_cb cb)
{
	auto hook = std::make_unique<whp_hook>();
	hook->cb = std::move(cb);
	hook->owner = this;
	hook->start = start_addr;
	hook->end = end_addr;
	hook->backend = hm_.get();

	auto& callback = std::get<code_hk_cb>(hook->cb);

	for (const auto& [begin, end] : phys_runs(start_addr, end_addr))
	{
		hook->native.push_back(hm_->hook_code(
			[this, &callback]
			{
				auto* const cpu = hook_cpu();
				callback(*cpu, cpu->pc(), 0);
			},
			begin, end));
	}

	return add_hook(std::move(hook));
}

emu::hook_handle x86_whp_emu::hook_basic_block(const addr_t start_addr, const addr_t end_addr,
	code_hk_cb cb)
{
	auto hook = std::make_unique<whp_hook>();
	hook->cb = std::move(cb);
	hook->owner = this;
	hook->start = start_addr;
	hook->end = end_addr;
	hook->backend = hm_.get();

	auto& callback = std::get<code_hk_cb>(hook->cb);

	for (const auto& [begin, end] : phys_runs(start_addr, end_addr))
	{
		hook->native.push_back(hm_->hook_basic_block(
			[this, &callback]
			{
				auto* const cpu = hook_cpu();
				callback(*cpu, cpu->pc(), 0);
			},
			begin, end));
	}

	return add_hook(std::move(hook));
}

emu::hook_handle x86_whp_emu::hook_invalid_mem(const mem_prot access, invalid_mem_hk_cb cb)
{
	auto hook = std::make_unique<whp_hook>();
	hook->cb = std::move(cb);
	hook->owner = this;
	hook->start = 1;
	hook->end = 0;
	hook->backend = hm_.get();

	auto& callback = std::get<invalid_mem_hk_cb>(hook->cb);

	hook->native.push_back(hm_->hook_invalid_mem(to_hm_prot(access),
		[this, &callback](const hm::addr_t addr, const hm::mem_vmexit::access type)
		{
			return callback(*hook_cpu(), addr, 0, to_prot(type));
		},
		0, 0));

	return add_hook(std::move(hook));
}

emu::hook_handle x86_whp_emu::hook_exception(exception_hk_cb cb)
{
	auto hook = std::make_unique<whp_hook>();
	hook->cb = std::move(cb);
	hook->owner = this;
	hook->start = 1;
	hook->end = 0;
	hook->backend = hm_.get();

	auto& callback = std::get<exception_hk_cb>(hook->cb);
	auto arch = arch_;

	hook->native.push_back(hm_->hook_exception(
		[this, &callback, arch](const hm::exception_id id)
		{
			return callback(*hook_cpu(), arch->intr_to_excp(static_cast<int>(id)));
		}));

	return add_hook(std::move(hook));
}

void x86_whp_emu::remove_hook(const hook_handle handle)
{
	std::erase_if(hooks_, [handle](const auto& hook) { return hook.get() == handle; });
}

void x86_whp_emu::map_phys_mem(const addr_t addr, const std::size_t size)
{
	// Physical pages are mapped wide open on purpose. What a page may be used
	// for is decided by the guest page tables the mmu writes, and the physical
	// protection is what the hooks spend: hypermulator serves one by taking a
	// permission away from the page and putting it back afterwards, and what it
	// puts back is everything the hook did not ask about. Mapping a page any
	// narrower than this would have a hook hand it permissions it never had.
	// The Unicorn backend arrives at the same place, since every region is
	// remapped rwx when an engine opens.
	if (!hm_->map_phys_mem(addr, size, hm::prot_rwx))
		throw std::runtime_error(std::format("failed to map 0x{:X} bytes at 0x{:X}", size, addr));
}

void x86_whp_emu::unmap_phys_mem(const addr_t addr, const std::size_t size, mem_prot)
{
	if (!hm_->unmap_phys_mem(addr, size))
		throw std::runtime_error(std::format("failed to unmap 0x{:X} bytes at 0x{:X}", size, addr));
}

void x86_whp_emu::read_phys_mem(const addr_t addr, void* const buf, const std::size_t size)
{
	if (!hm_->read_phys_mem(addr, buf, size))
		throw std::runtime_error(std::format("failed to read 0x{:X} bytes at 0x{:X}", size, addr));
}

void x86_whp_emu::write_phys_mem(const addr_t addr, const void* const buf, const std::size_t size)
{
	if (!hm_->write_phys_mem(addr, buf, size))
		throw std::runtime_error(std::format("failed to write 0x{:X} bytes at 0x{:X}", size, addr));
}

#endif
