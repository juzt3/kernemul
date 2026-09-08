#pragma once
#include "arch.hpp"
#include "defs.hpp"
#include <functional>
#include <expected>
#include <memory>
#include <span>
#include <vector>

class emu;
struct emu_hook;

class vcpu
{
public:
	vcpu(emu* const emu, std::shared_ptr<const arch> arch)
		:	emu_(emu), arch_(std::move(arch)) { }

	virtual ~vcpu() = default;

	virtual void run() = 0;

	[[nodiscard]] std::shared_ptr<const arch> arch() const noexcept
	{
		return arch_;
	}

protected:
	emu* emu_;
	std::shared_ptr<const struct arch> arch_;
};

class emu
{
public:
	explicit emu(std::shared_ptr<const arch> arch)
		:	arch_(std::move(arch)) { }

	virtual ~emu() = default;

	using hook_handle = emu_hook*;
	using mem_hk_cb = std::function<void(vcpu&, addr_t, std::size_t, mem_prot)>;

	[[nodiscard]] std::shared_ptr<const arch> arch() const noexcept
	{
		return arch_;
	}

	[[nodiscard]] std::shared_ptr<vcpu> add_vcpu()
	{
		auto cpu = create_vcpu();

		cpus_.push_back(cpu);

		return cpu;
	}

	virtual hook_handle hook_mem(addr_t start_addr, addr_t end_addr, mem_prot prot, mem_hk_cb) = 0;
	virtual void remove_hook(hook_handle handle) = 0;

	virtual void map_mem(addr_t addr, std::size_t size, mem_prot prot) = 0;
	virtual void unmap_mem(addr_t addr, std::size_t size, mem_prot prot) = 0;
	virtual void read_mem(addr_t addr, void* buf, std::size_t size) = 0;
	virtual void write_mem(addr_t addr, const void* buf, std::size_t size) = 0;

	[[nodiscard]] std::span<const std::shared_ptr<vcpu>> cpus() const noexcept
	{
		return cpus_;
	}

protected:
	virtual std::shared_ptr<vcpu> create_vcpu() = 0;

	std::shared_ptr<const struct arch> arch_;
	std::vector<std::shared_ptr<vcpu>> cpus_;
};
