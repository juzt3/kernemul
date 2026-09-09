#include "arch.hpp"
#include "../emu.hpp"

namespace ia32 {
#include <ia32.hpp>
}

namespace x86
{

void arch::init_vcpu(vcpu& cpu)
{
	auto* mem = emu_->mem().get();

	constexpr std::uint32_t tss_limit = 103;
	addr_t tss_pa = mem->alloc_phys(tss_limit + 1, prot_rw);

	constexpr std::size_t gdt_size = 3 * sizeof(ia32::segment_descriptor_32)
		+ sizeof(ia32::segment_descriptor_64);
	addr_t gdt_pa = mem->alloc_phys(gdt_size, prot_rw);

	mem->write_phys<ia32::segment_descriptor_32>(gdt_pa + 0x00, {});

	ia32::segment_descriptor_32 code_desc{};
	code_desc.segment_limit_low = 0xFFFF;
	code_desc.segment_limit_high = 0xF;
	code_desc.type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
	code_desc.descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
	code_desc.present = 1;
	code_desc.long_mode = 1;
	code_desc.granularity = 1;
	mem->write_phys(gdt_pa + 0x08, code_desc);

	ia32::segment_descriptor_32 data_desc{};
	data_desc.segment_limit_low = 0xFFFF;
	data_desc.segment_limit_high = 0xF;
	data_desc.type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
	data_desc.descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
	data_desc.present = 1;
	data_desc.default_big = 1;
	data_desc.granularity = 1;
	mem->write_phys(gdt_pa + 0x10, data_desc);

	ia32::segment_descriptor_64 tss_desc{};
	tss_desc.base_address_low = static_cast<std::uint16_t>(tss_pa);
	tss_desc.base_address_middle = (tss_pa >> 16) & 0xFF;
	tss_desc.base_address_high = (tss_pa >> 24) & 0xFF;
	tss_desc.base_address_upper = static_cast<std::uint32_t>(tss_pa >> 32);
	tss_desc.segment_limit_low = static_cast<std::uint16_t>(tss_limit);
	tss_desc.type = SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY;
	tss_desc.present = 1;
	mem->write_phys(gdt_pa + 0x18, tss_desc);

	constexpr std::size_t idt_size = 256 * sizeof(ia32::segment_descriptor_interrupt_gate_64);
	addr_t idt_pa = mem->alloc_phys(idt_size, prot_rw);

	cpu.reg(x86::gdtr, seg_reg{ 0, gdt_pa, static_cast<std::uint32_t>(gdt_size - 1), 0 });
	cpu.reg(x86::idtr, seg_reg{ 0, idt_pa, static_cast<std::uint32_t>(idt_size - 1), 0 });

	ia32::segment_access_rights tr_access{};
	tr_access.type = SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY;
	tr_access.present = 1;
	cpu.reg(x86::tr, seg_reg{ 0x18, tss_pa, tss_limit, tr_access.flags });

	ia32::segment_access_rights cs_access{};
	cs_access.type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
	cs_access.descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
	cs_access.present = 1;
	cs_access.long_mode = 1;
	cs_access.granularity = 1;
	cpu.reg(x86::cs, seg_reg{ 0x08, 0, 0xFFFFFFFF, cs_access.flags });

	ia32::segment_access_rights data_access{};
	data_access.type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
	data_access.descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
	data_access.present = 1;
	data_access.default_big = 1;
	data_access.granularity = 1;
	seg_reg data_sr{ 0x10, 0, 0xFFFFFFFF, data_access.flags };
	cpu.reg(x86::ss, data_sr);
	cpu.reg(x86::ds, data_sr);
	cpu.reg(x86::es, data_sr);

	cpu.reg(x86::fs, seg_reg{});
	cpu.reg(x86::gs, seg_reg{});
	cpu.reg(x86::ldtr, seg_reg{});
}

}
