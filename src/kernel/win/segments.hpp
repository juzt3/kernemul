#pragma once
#include "../../emu/emu.hpp"
#include "../../emu/x86/arch.hpp"
#include <cstdint>

struct proc_module;

namespace x86_win_seg
{
	constexpr std::uint16_t kernel_cs = 0x10;
	constexpr std::uint16_t kernel_ds = 0x18;
	constexpr std::uint16_t user_ds   = 0x2B;
	constexpr std::uint16_t user_cs   = 0x33;
	constexpr std::uint16_t tss_sel   = 0x40;

	// Where a cpu's descriptor tables ended up. The KPCR carries the same
	// pointers, and the cpu that owns them is the only thing that knows where
	// they are.
	struct cpu_tables
	{
		addr_t gdt = 0;
		addr_t tss = 0;
		addr_t idt = 0;
	};

	// Everything a cpu needs before it can run kernel code: the GDT, the TSS,
	// the segment registers and the IDT. ntoskrnl is needed because the IDT's
	// handlers are its symbols.
	cpu_tables init_vcpu(vcpu& cpu, const proc_module& ntoskrnl);

	void set_kernel_gs(vcpu& cpu, std::uint64_t base);
	void set_usermode_gs(vcpu& cpu, std::uint64_t teb_addr);

	x86::seg_reg make_usermode_gs(std::uint64_t teb_addr);

	// As values, for a thread that is not on a cpu yet.
	x86::seg_reg make_usermode_cs();
	x86::seg_reg make_usermode_ss();

	void swap_to_kernel_segments(vcpu& cpu);
	void swap_to_usermode_segments(vcpu& cpu);
}
