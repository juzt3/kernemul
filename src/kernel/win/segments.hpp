#pragma once
#include "../../emu/emu.hpp"
#include "../../emu/x86/arch.hpp"
#include <cstdint>

namespace x86_win_seg
{
	constexpr std::uint16_t kernel_cs = 0x10;
	constexpr std::uint16_t kernel_ds = 0x18;
	constexpr std::uint16_t user_ds   = 0x2B;
	constexpr std::uint16_t user_cs   = 0x33;
	constexpr std::uint16_t tss_sel   = 0x40;

	void init_vcpu(vcpu& cpu);

	void set_kernel_gs(vcpu& cpu, std::uint64_t base);
	void set_usermode_gs(vcpu& cpu, std::uint64_t teb_addr);

	void swap_to_kernel_segments(vcpu& cpu);
	void swap_to_usermode_segments(vcpu& cpu);
}
