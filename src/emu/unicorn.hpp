#pragma once
#include "emu.hpp"

#include <unicorn/unicorn.h>
#include <atomic>
#include <cstring>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <list>

namespace ia32 {
#include <ia32.hpp>
}

struct unicorn_hook : emu_hook
{
	int uc_type;
	int uc_insn;
	std::vector<uc_hook> handles;
};

class unicorn_vcpu : public vcpu
{
public:
	unicorn_vcpu(emu* emu, std::shared_ptr<const struct arch> arch, uc_engine* uc)
		:	vcpu(emu, std::move(arch)), uc_(uc) { }

	~unicorn_vcpu() override
	{
		if (uc_) uc_close(uc_);
	}

	void run() override
	{
		for (;;)
		{
			running_ = true;
			auto pc = reg<addr_t>(arch_->pc());
			uc_emu_start(uc_, pc, std::numeric_limits<addr_t>::max(), 0, 0);
			running_ = false;

			if (!pending_pause_.load())
				break;

			while (pending_pause_.load()) {}
		}
	}

	void stop() override
	{
		uc_emu_stop(uc_);
	}

	void flush_tlb() override
	{
		uc_ctl_flush_tlb(uc_);
	}

	void reg_read(reg_t reg, void* value, std::size_t size) override
	{
		if (reg == x86::efer)
		{
			uc_x86_msr msr{ IA32_EFER, 0 };
			uc_reg_read(uc_, UC_X86_REG_MSR, &msr);
			std::memcpy(value, &msr.value, std::min(size, sizeof(msr.value)));
			return;
		}
		uc_reg_read(uc_, to_uc_reg(reg), value);
	}

	void reg_write(reg_t reg, const void* value, std::size_t size) override
	{
		if (reg == x86::efer)
		{
			std::uint64_t val{};
			std::memcpy(&val, value, std::min(size, sizeof(val)));
			uc_x86_msr msr{ IA32_EFER, val };
			uc_reg_write(uc_, UC_X86_REG_MSR, &msr);
			return;
		}
		uc_reg_write(uc_, to_uc_reg(reg), value);
	}

	uc_engine* native() const { return uc_; }

	static constexpr int to_uc_reg(reg_t reg)
	{
		switch (reg)
		{
		case x86::rax:    return UC_X86_REG_RAX;
		case x86::rcx:    return UC_X86_REG_RCX;
		case x86::rdx:    return UC_X86_REG_RDX;
		case x86::rbx:    return UC_X86_REG_RBX;
		case x86::rsp:    return UC_X86_REG_RSP;
		case x86::rbp:    return UC_X86_REG_RBP;
		case x86::rsi:    return UC_X86_REG_RSI;
		case x86::rdi:    return UC_X86_REG_RDI;
		case x86::r8:     return UC_X86_REG_R8;
		case x86::r9:     return UC_X86_REG_R9;
		case x86::r10:    return UC_X86_REG_R10;
		case x86::r11:    return UC_X86_REG_R11;
		case x86::r12:    return UC_X86_REG_R12;
		case x86::r13:    return UC_X86_REG_R13;
		case x86::r14:    return UC_X86_REG_R14;
		case x86::r15:    return UC_X86_REG_R15;
		case x86::rip:    return UC_X86_REG_RIP;
		case x86::rflags: return UC_X86_REG_RFLAGS;
		case x86::cr0:    return UC_X86_REG_CR0;
		case x86::cr3:    return UC_X86_REG_CR3;
		case x86::cr4:    return UC_X86_REG_CR4;
		default: return -1;
		}
	}

	uc_engine* uc_;
	std::atomic<bool> running_{false};
	std::atomic<bool> pending_pause_{false};
};

class unicorn_emu : public emu
{
public:
	unicorn_emu(std::shared_ptr<const struct arch> arch, std::shared_ptr<mmu> mem)
		:	emu(std::move(arch), std::move(mem)) { }

	void map_phys_mem(addr_t addr, std::size_t size, mem_prot prot) override
	{
		auto it = mem_.find(addr);
		std::size_t old_size = (it != mem_.end()) ? it->second.size() : 0;

		auto& buf = mem_[addr];
		buf.resize(size);

		run_on_all([&] {
			for (auto& cpu : cpus_)
			{
				if (old_size)
					uc_mem_unmap(engine(cpu), addr, old_size);
				uc_mem_map_ptr(engine(cpu), addr, size, prot, buf.data());
			}
		});
	}

	void unmap_phys_mem(addr_t addr, std::size_t size, mem_prot) override
	{
		run_on_all([&] {
			for (auto& cpu : cpus_)
				uc_mem_unmap(engine(cpu), addr, size);
		});

		mem_.erase(addr);
	}

	void read_phys_mem(addr_t addr, void* buf, std::size_t size) override
	{
		auto [src, avail] = find_backing(addr);
		if (src)
			std::memcpy(buf, src, std::min(size, avail));
	}

	void write_phys_mem(addr_t addr, const void* buf, std::size_t size) override
	{
		auto [dst, avail] = find_backing(addr);
		if (dst)
			std::memcpy(dst, buf, std::min(size, avail));
	}

	hook_handle hook_mem(addr_t start_addr, addr_t end_addr, mem_prot prot, mem_hk_cb cb) override
	{
		hooks_.push_back({});
		auto& hk = hooks_.back();
		hk.cb = std::move(cb);
		hk.owner = this;
		hk.start = start_addr;
		hk.end = end_addr;
		hk.uc_type = prot_to_uc_hook(prot);
		hk.uc_insn = 0;

		for (auto& cpu : cpus_)
			add_uc_hook(hk, engine(cpu));

		return &hk;
	}

	hook_handle hook_insn(addr_t start_addr, addr_t end_addr, hook_insn_t insn, insn_hk_cb cb) override
	{
		hooks_.push_back({});
		auto& hk = hooks_.back();
		hk.cb = std::move(cb);
		hk.owner = this;
		hk.start = start_addr;
		hk.end = end_addr;
		hk.uc_type = UC_HOOK_INSN;
		hk.uc_insn = to_uc_insn(insn);

		for (auto& cpu : cpus_)
			add_uc_hook(hk, engine(cpu));

		return &hk;
	}

	hook_handle hook_code(addr_t start_addr, addr_t end_addr, code_hk_cb cb) override
	{
		hooks_.push_back({});
		auto& hk = hooks_.back();
		hk.cb = std::move(cb);
		hk.owner = this;
		hk.start = start_addr;
		hk.end = end_addr;
		hk.uc_type = UC_HOOK_CODE;
		hk.uc_insn = 0;

		for (auto& cpu : cpus_)
			add_uc_hook(hk, engine(cpu));

		return &hk;
	}

	hook_handle hook_basic_block(addr_t start_addr, addr_t end_addr, code_hk_cb cb) override
	{
		hooks_.push_back({});
		auto& hk = hooks_.back();
		hk.cb = std::move(cb);
		hk.owner = this;
		hk.start = start_addr;
		hk.end = end_addr;
		hk.uc_type = UC_HOOK_BLOCK;
		hk.uc_insn = 0;

		for (auto& cpu : cpus_)
			add_uc_hook(hk, engine(cpu));

		return &hk;
	}

	hook_handle hook_invalid_mem(mem_prot access, invalid_mem_hk_cb cb) override
	{
		hooks_.push_back({});
		auto& hk = hooks_.back();
		hk.cb = std::move(cb);
		hk.owner = this;
		hk.start = 1;
		hk.end = 0;
		hk.uc_type = prot_to_uc_hook_unmapped(access);
		hk.uc_insn = 0;

		for (auto& cpu : cpus_)
			add_uc_hook(hk, engine(cpu));

		return &hk;
	}

	void remove_hook(hook_handle handle) override
	{
		auto* hk = static_cast<unicorn_hook*>(handle);

		for (std::size_t i = 0; i < hk->handles.size(); ++i)
			uc_hook_del(engine(cpus_[i]), hk->handles[i]);

		hooks_.remove_if([hk](const unicorn_hook& h) { return &h == hk; });
	}

protected:
	std::shared_ptr<vcpu> create_vcpu() override
	{
		uc_engine* uc = nullptr;

		if (dynamic_cast<const x86::arch*>(arch_.get()))
			uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
		else
			throw std::runtime_error("unsupported architecture for unicorn backend");

		for (auto& [addr, buf] : mem_)
			uc_mem_map_ptr(uc, addr, buf.size(), prot_all, buf.data());

		for (auto& hk : hooks_)
			add_uc_hook(hk, uc);

		uc_ctl_tlb_mode(uc, UC_TLB_CPU);

		return std::make_shared<unicorn_vcpu>(this, arch_, uc);
	}

private:
	static void mem_hook_trampoline(uc_engine* uc, uc_mem_type type, std::uint64_t addr,
		int size, std::int64_t, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu*>(hk->owner);
		auto& cb = std::get<mem_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				cb(*cpu, addr, static_cast<std::size_t>(size), uc_type_to_prot(type));
				return;
			}
		}
	}

	static void insn_hook_trampoline(uc_engine* uc, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu*>(hk->owner);
		auto& cb = std::get<insn_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				cb(*cpu);
				return;
			}
		}
	}

	static void code_hook_trampoline(uc_engine* uc, std::uint64_t addr,
		std::uint32_t size, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu*>(hk->owner);
		auto& cb = std::get<code_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				cb(*cpu, addr, static_cast<std::size_t>(size));
				return;
			}
		}
	}

	static bool invalid_mem_hook_trampoline(uc_engine* uc, uc_mem_type type,
		std::uint64_t addr, int size, std::int64_t, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu*>(hk->owner);
		auto& cb = std::get<invalid_mem_hk_cb>(hk->cb);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
				return cb(*cpu, addr, static_cast<std::size_t>(size), uc_type_to_prot(type));
		}

		return false;
	}

	static void add_uc_hook(unicorn_hook& hk, uc_engine* uc)
	{
		uc_hook h{};
		if (hk.uc_type == UC_HOOK_INSN)
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(insn_hook_trampoline),
				&hk, hk.start, hk.end, hk.uc_insn);
		else if (hk.uc_type == UC_HOOK_CODE || hk.uc_type == UC_HOOK_BLOCK)
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(code_hook_trampoline),
				&hk, hk.start, hk.end);
		else if (hk.uc_type & (UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED))
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(invalid_mem_hook_trampoline),
				&hk, hk.start, hk.end);
		else
			uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(mem_hook_trampoline),
				&hk, hk.start, hk.end);
		hk.handles.push_back(h);
	}

	static constexpr int to_uc_insn(hook_insn_t insn)
	{
		switch (insn)
		{
		case hook_insn_t::cpuid: return UC_X86_INS_CPUID;
		case hook_insn_t::rdtsc: return UC_X86_INS_RDTSC;
		default: return -1;
		}
	}

	static int prot_to_uc_hook(mem_prot p)
	{
		int type = 0;
		if (p & prot_read)  type |= UC_HOOK_MEM_READ;
		if (p & prot_write) type |= UC_HOOK_MEM_WRITE;
		if (p & prot_exec)  type |= UC_HOOK_MEM_FETCH;
		return type;
	}

	static int prot_to_uc_hook_unmapped(mem_prot p)
	{
		int type = 0;
		if (p & prot_read)  type |= UC_HOOK_MEM_READ_UNMAPPED;
		if (p & prot_write) type |= UC_HOOK_MEM_WRITE_UNMAPPED;
		if (p & prot_exec)  type |= UC_HOOK_MEM_FETCH_UNMAPPED;
		return type;
	}

	static mem_prot uc_type_to_prot(uc_mem_type type)
	{
		switch (type)
		{
		case UC_MEM_READ:       return prot_read;
		case UC_MEM_WRITE:      return prot_write;
		case UC_MEM_FETCH:      return prot_exec;
		case UC_MEM_READ_AFTER: return prot_read;
		default:                return prot_none;
		}
	}

	static uc_engine* engine(const std::shared_ptr<vcpu>& cpu)
	{
		return static_cast<unicorn_vcpu*>(cpu.get())->native();
	}

	std::pair<std::uint8_t*, std::size_t> find_backing(addr_t addr)
	{
		for (auto& [base, buf] : mem_)
		{
			if (addr >= base && addr < base + buf.size())
			{
				auto off = addr - base;
				return { buf.data() + off, buf.size() - off };
			}
		}
		return { nullptr, 0 };
	}

	void run_on_all(std::function<void()> fn)
	{
		std::lock_guard lk(op_mtx_);
		for (auto& cpu : cpus_)
		{
			auto* uc = static_cast<unicorn_vcpu*>(cpu.get());
			uc->pending_pause_ = true;
			uc->stop();
		}
		for (auto& cpu : cpus_)
			while (static_cast<unicorn_vcpu*>(cpu.get())->running_.load()) {}

		fn();

		for (auto& cpu : cpus_)
			static_cast<unicorn_vcpu*>(cpu.get())->pending_pause_ = false;
	}

	std::unordered_map<addr_t, std::vector<std::uint8_t>> mem_;
	std::list<unicorn_hook> hooks_;
	std::mutex op_mtx_;
};
