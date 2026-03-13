#pragma once

#include "../emulator/emulator.hpp"
#include "../image/mapped_image.hpp"

#include <ia32-doc/ia32.hpp>

constexpr std::uint32_t kernel_cpl = 0;
constexpr std::uint32_t usermode_cpl = 3;

constexpr std::uint16_t kernel_cs_selector = 2 * sizeof(segment_descriptor_32);
constexpr std::uint16_t kernel_ds_selector = 3 * sizeof(segment_descriptor_32);
constexpr std::uint16_t tss_selector_value = 8 * sizeof(segment_descriptor_32);

constexpr std::uint32_t segment_limit = 0xFFFFF;

constexpr std::uint16_t data_segment_attributes =
	SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED
	| (1 << 4)
	| (kernel_cpl << 5)
	| (1 << 7);

constexpr std::uint16_t code_segment_attributes =
	SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED
	| (1 << 4)
	| (kernel_cpl << 5)
	| (1 << 7)
	| (1 << 13);

constexpr std::uint16_t tss_attributes = 0x008B;

segment_descriptor_32 make_gdt_descriptor(std::uint32_t privilege_level);
segment_descriptor_32 make_code_gdt_descriptor(std::uint32_t privilege_level, bool is_long = true);
segment_descriptor_32 make_data_gdt_descriptor(std::uint32_t privilege_level);

void set_up_gdt(const std::shared_ptr<emulator_t>& emulator);
void set_up_segments(const std::shared_ptr<emulator_t>& emulator);
void set_up_kernel_gs(const std::shared_ptr<emulator_t>& emulator, emulator_t::address_type kpcr_address);
void set_up_idt(const std::shared_ptr<emulator_t>& emulator, const mapped_image_t& nt_image);
