#pragma once
#include "arch.hpp"
#include "defs.hpp"
#include <functional>
#include <expected>
#include <memory>
#include <span>
#include <vector>

class emu;

class vcpu
{
public:
	vcpu(emu* const emu, std::shared_ptr<const arch> arch)
		:	emu_(emu), arch_(std::move(arch)) { }

	virtual ~vcpu() = default;

	virtual void run() = 0;
	virtual void stop() = 0;

	virtual void reg_read(reg_t reg, void* value, std::size_t size) = 0;
	virtual void reg_write(reg_t reg, const void* value, std::size_t size) = 0;

	template <reg_t R, typename T = std::uint64_t>
	T reg()
	{
		T v{};
		reg_read(R, &v, sizeof(v));
		return v;
	}

	template <reg_t R, typename T = std::uint64_t>
	void reg(const T& v)
	{
		reg_write(R, &v, sizeof(v));
	}

	template <typename T = std::uint64_t>
	T reg(reg_t r)
	{
		T v{};
		reg_read(r, &v, sizeof(v));
		return v;
	}

	template <typename T = std::uint64_t>
	void reg(reg_t r, const T& v)
	{
		reg_write(r, &v, sizeof(v));
	}

	[[nodiscard]] std::shared_ptr<const arch> arch() const noexcept
	{
		return arch_;
	}

protected:
	emu* emu_;
	std::shared_ptr<const struct arch> arch_;
};

using mem_hk_cb = std::function<void(vcpu&, addr_t, std::size_t, mem_prot)>;

struct emu_hook
{
	virtual ~emu_hook() = default;

	mem_hk_cb cb;
	emu* owner;
};

class emu
{
public:
	explicit emu(std::shared_ptr<const arch> arch)
		:	arch_(std::move(arch)) { }

	virtual ~emu() = default;

	using hook_handle = emu_hook*;

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
