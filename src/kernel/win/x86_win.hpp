#pragma once
#include "win_kernel.hpp"
#include "segments.hpp"

// Windows on x86-64: the TEB is reached through the GS base, and the CPU needs
// a GDT, a TSS and an IDT before any of that works. The KPCR shares that same
// GS base, which is why a thread going on a cpu has to put its cpu's block back
// -- see win_thread::restore.
class x86_win_emulator : public windows_emulator
{
public:
	using windows_emulator::windows_emulator;

	std::shared_ptr<vcpu> add_vcpu() override
	{
		auto cpu = emu_->add_vcpu();

		// None of a cpu's state is worth building without ntoskrnl: the IDT's
		// handlers are its symbols, and a machine that could not map it has
		// nothing to run anyway.
		if (const auto nt = kernel().sys_proc->find_module("ntoskrnl.exe"))
		{
			const auto tables = x86_win_seg::init_vcpu(*cpu, *nt);

			// After the tables, because the KPCR carries the pointers to them
			// and the guest reads its own descriptor tables back out of it.
			const auto& pcpu = kernel().init_per_cpu(*cpu);
			auto& space = *pcpu.space();

			space.write_mem<addr_t>(pcpu.address() + offsetof(_KPCR, GdtBase), tables.gdt);
			space.write_mem<addr_t>(pcpu.address() + offsetof(_KPCR, TssBase), tables.tss);
			space.write_mem<addr_t>(pcpu.address() + offsetof(_KPCR, IdtBase), tables.idt);

			set_pcr(*cpu, pcpu.address());
		}

		return cpu;
	}

	void set_pcr(vcpu& cpu, const addr_t kpcr_va) override
	{
		x86_win_seg::set_kernel_gs(cpu, kpcr_va);
	}

	void init_thread_teb(thread& t, vcpu& cpu, addr_t teb_addr) override
	{
		t.set_reg_val(cpu, x86::gs, x86_win_seg::make_usermode_gs(teb_addr));
	}
};
