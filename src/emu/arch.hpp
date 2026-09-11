#pragma once
#include "defs.hpp"
#include <cstddef>
#include <span>

using reg_t = int;

class emu;
class vcpu;

struct arch
{
	virtual ~arch() = default;
	virtual reg_t pc() const = 0;
	virtual reg_t sp() const = 0;
	virtual addr_t ret_addr(vcpu& cpu) const = 0;
	virtual void init_vcpu(vcpu&) {}
	virtual std::span<const reg_t> regs() const = 0;

	void set_emu(emu* e) { emu_ = e; }

protected:
	emu* emu_ = nullptr;
};

#include "x86/arch.hpp"
