#pragma once
#include "emu.hpp"

#include <unicorn/unicorn.h>
#include <stdexcept>
#include <unordered_map>
#include <list>

struct unicorn_hook : emu_hook
{
	addr_t start, end;
	int uc_type;
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
	}

	uc_engine* native() const { return uc_; }

private:
	uc_engine* uc_;
};

class unicorn_emu : public emu
{
public:
	explicit unicorn_emu(std::shared_ptr<const struct arch> arch)
		:	emu(std::move(arch)) { }

	void map_mem(addr_t addr, std::size_t size, mem_prot prot) override
	{
		auto& buf = mem_[addr];
		buf.resize(size);

		for (auto& cpu : cpus_)
			uc_mem_map_ptr(engine(cpu), addr, size, prot, buf.data());
	}

	void unmap_mem(addr_t addr, std::size_t size, mem_prot) override
	{
		for (auto& cpu : cpus_)
			uc_mem_unmap(engine(cpu), addr, size);

		mem_.erase(addr);
	}

	void read_mem(addr_t addr, void* buf, std::size_t size) override
	{
		uc_mem_read(engine(cpus_[0]), addr, buf, size);
	}

	void write_mem(addr_t addr, const void* buf, std::size_t size) override
	{
		uc_mem_write(engine(cpus_[0]), addr, buf, size);
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

		if (dynamic_cast<const x86_arch*>(arch_.get()))
			uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
		else
			throw std::runtime_error("unsupported architecture for unicorn backend");

		for (auto& [addr, buf] : mem_)
			uc_mem_map_ptr(uc, addr, buf.size(), prot_all, buf.data());

		for (auto& hk : hooks_)
			add_uc_hook(hk, uc);

		return std::make_shared<unicorn_vcpu>(this, arch_, uc);
	}

private:
	static void mem_hook_trampoline(uc_engine* uc, uc_mem_type type, std::uint64_t addr,
		int size, std::int64_t, void* user_data)
	{
		auto* hk = static_cast<unicorn_hook*>(user_data);
		auto* self = static_cast<unicorn_emu*>(hk->owner);

		for (auto& cpu : self->cpus_)
		{
			if (engine(cpu) == uc)
			{
				hk->cb(*cpu, addr, static_cast<std::size_t>(size), uc_type_to_prot(type));
				return;
			}
		}
	}

	static void add_uc_hook(unicorn_hook& hk, uc_engine* uc)
	{
		uc_hook h{};
		uc_hook_add(uc, &h, hk.uc_type, reinterpret_cast<void*>(mem_hook_trampoline),
			&hk, hk.start, hk.end);
		hk.handles.push_back(h);
	}

	static int prot_to_uc_hook(mem_prot p)
	{
		int type = 0;
		if (p & prot_read)  type |= UC_HOOK_MEM_READ;
		if (p & prot_write) type |= UC_HOOK_MEM_WRITE;
		if (p & prot_exec)  type |= UC_HOOK_MEM_FETCH;
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

	std::unordered_map<addr_t, std::vector<std::uint8_t>> mem_;
	std::list<unicorn_hook> hooks_;
};
