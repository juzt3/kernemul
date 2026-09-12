#pragma once
#include "win_kernel.hpp"
#include "../../emu/arm64/arch.hpp"

// Windows on ARM64. There is no GDT, no TSS and no IDT: the TEB lives in
// TPIDR_EL0, the KPCR in TPIDR_EL1, and the exception vectors are found through
// VBAR_EL1 rather than a descriptor table.
class arm64_win_emulator : public windows_emulator
{
public:
	using windows_emulator::windows_emulator;

	std::shared_ptr<vcpu> add_vcpu() override;

	void set_pcr(vcpu& cpu, const addr_t kpcr_va) override
	{
		cpu.reg(arm64::tpidr_el1, kpcr_va);
	}

	void init_thread_teb(thread& t, vcpu& cpu, addr_t teb_addr) override
	{
		t.set_reg(cpu, arm64::tpidr_el0, teb_addr);
	}
};
