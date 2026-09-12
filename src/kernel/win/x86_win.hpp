#pragma once
#include "win_kernel.hpp"
#include "segments.hpp"

// Windows on x86-64: the TEB is reached through the GS base, and the CPU needs
// a GDT, a TSS and an IDT before any of that works.
class x86_win_emulator : public windows_emulator
{
public:
	using windows_emulator::windows_emulator;

	std::shared_ptr<vcpu> add_vcpu() override
	{
		auto cpu = emu_->add_vcpu();
		x86_win_seg::init_vcpu(*cpu);

		if (auto nt = kernel().sys_proc->find_module("ntoskrnl.exe"))
			x86_win_seg::init_idt(*cpu, *nt);

		return cpu;
	}

	void init_thread_teb(thread& t, vcpu& cpu, addr_t teb_addr) override
	{
		t.set_reg_val(cpu, x86::gs, x86_win_seg::make_usermode_gs(teb_addr));
	}
};
