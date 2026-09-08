#pragma once
#include "emu.hpp"

#include <unicorn/unicorn.h>
#include <stdexcept>
#include <unordered_map>

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

	hook_handle hook_mem(addr_t, addr_t, mem_prot, mem_hk_cb) override
	{
		return nullptr;
	}

	void remove_hook(hook_handle) override { }

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

		return std::make_shared<unicorn_vcpu>(this, arch_, uc);
	}

private:
	static uc_engine* engine(const std::shared_ptr<vcpu>& cpu)
	{
		return static_cast<unicorn_vcpu*>(cpu.get())->native();
	}

	std::unordered_map<addr_t, std::vector<std::uint8_t>> mem_;
};
