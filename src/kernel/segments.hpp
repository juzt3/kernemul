#pragma once

#include "../emulator/emulator.hpp"
#include "../image/mapped_image.hpp"

namespace kernel
{
	constexpr std::uint32_t kernelmode_cpl = 0;
	constexpr std::uint32_t usermode_cpl = 3;

	void set_up_gdt(const std::shared_ptr<emulator_t>& emulator);
	void set_up_segments(const std::shared_ptr<emulator_t>& emulator);
	void set_up_kernel_gs(const std::shared_ptr<emulator_t>& emulator, emulator_t::address_type kpcr_address);
	void set_up_idt(const std::shared_ptr<emulator_t>& emulator, const mapped_image_t& nt_image);
}
