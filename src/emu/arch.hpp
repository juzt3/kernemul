#pragma once
#include "defs.hpp"
#include <cstddef>
#include <cstdint>
#include <span>

using reg_t = int;

struct alignas(16) reg_val
{
	std::uint64_t gp{};
	std::uint64_t pad_[3]{};
};

class emu;
class vcpu;

enum class cpu_exception : std::uint8_t;

struct arch
{
	virtual ~arch() = default;
	virtual reg_t pc() const = 0;
	virtual reg_t sp() const = 0;
	virtual addr_t ret_addr(vcpu& cpu) const = 0;
	virtual void init_vcpu(vcpu&) {}
	virtual std::span<const reg_t> regs() const = 0;
	virtual std::size_t reg_size(reg_t r) const = 0;
	virtual cpu_exception intr_to_excp(int vector) const = 0;
	virtual addr_t fault_addr(vcpu& cpu) const = 0;

	void set_emu(emu* e) { emu_ = e; }

protected:
	emu* emu_ = nullptr;
};

#include "x86/arch.hpp"
