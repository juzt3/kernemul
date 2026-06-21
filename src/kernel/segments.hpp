#pragma once

#include "../emulator/emulator.hpp"
#include "../image/mapped_image.hpp"

namespace kernel
{
	constexpr std::uint32_t kernelmode_cpl = 0;
	constexpr std::uint32_t usermode_cpl = 3;

	constexpr std::uint16_t kernel_cs_selector = 0x10;
	constexpr std::uint16_t kernel_ds_selector = 0x18;
	constexpr std::uint16_t user_cs_selector = 0x33;
	constexpr std::uint16_t user_ds_selector = 0x2B;

	constexpr std::uint32_t segment_limit = 0xFFFFF;
	constexpr std::uint16_t kernel_code_attributes = 0x209B;
	constexpr std::uint16_t kernel_data_attributes = 0x20B3;
	constexpr std::uint16_t user_code_attributes = 0x20FB;
	constexpr std::uint16_t user_data_attributes = 0x20F3;

	void set_up_gdt(const std::shared_ptr<emulator_t>& emulator);
	void set_up_segments(const std::shared_ptr<emulator_t>& emulator);
	void set_up_kernel_gs(const std::shared_ptr<emulator_t>& emulator, emulator_t::address_type kpcr_address);
	void set_up_idt(const std::shared_ptr<emulator_t>& emulator, const image_t& nt_image);

	void swap_to_kernel_gs(const std::shared_ptr<emulator_t>& emulator);
	void swap_to_usermode_gs(const std::shared_ptr<emulator_t>& emulator, emulator_t::address_type teb_address);

	void swap_to_kernel_segments(const std::shared_ptr<emulator_t>& emulator);
	void swap_to_usermode_segments(const std::shared_ptr<emulator_t>& emulator);
}
