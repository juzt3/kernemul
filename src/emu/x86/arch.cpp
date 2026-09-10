#include "arch.hpp"
#include "../emu.hpp"

namespace ia32 {
#include <ia32.hpp>
}

namespace x86
{

static ia32::segment_descriptor_32 make_gdt_desc(std::uint32_t dpl)
{
	ia32::segment_descriptor_32 desc{};
	desc.present = 1;
	desc.granularity = 1;
	desc.descriptor_privilege_level = dpl;
	desc.descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
	desc.segment_limit_low = 0xFFFF;
	desc.segment_limit_high = 0xF;
	return desc;
}

static ia32::segment_descriptor_32 make_code_desc(std::uint32_t dpl)
{
	auto desc = make_gdt_desc(dpl);
	desc.type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
	desc.long_mode = 1;
	return desc;
}

static ia32::segment_descriptor_32 make_data_desc(std::uint32_t dpl)
{
	auto desc = make_gdt_desc(dpl);
	desc.type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
	desc.default_big = 1;
	return desc;
}

addr_t arch::ret_addr(vcpu& cpu) const
{
	const auto ret = cpu.read_virt_mem<addr_t>(cpu.reg(rsp));
	cpu.reg(rsp, cpu.reg(rsp) + sizeof(addr_t));
	return ret;
}

void arch::init_vcpu(vcpu& cpu)
{
	auto* mem = emu_->mem().get();

	constexpr std::uint32_t tss_limit = 103;
	addr_t tss_pa = mem->alloc_phys(tss_limit + 1, prot_rw);

	// Windows-style GDT layout (11 entries, 88 bytes)
	// 0x00  null
	// 0x08  null (reserved)
	// 0x10  kernel CS
	// 0x18  kernel DS
	// 0x20  null (reserved)
	// 0x28  user DS  (DPL=3)
	// 0x30  user CS  (DPL=3)
	// 0x38  null (reserved)
	// 0x40  TSS low  (16-byte descriptor)
	// 0x48  TSS high
	// 0x50  null (reserved)
	constexpr std::size_t gdt_entries = 11;
	constexpr std::size_t gdt_size = gdt_entries * sizeof(ia32::segment_descriptor_32);
	addr_t gdt_pa = mem->alloc_phys(gdt_size, prot_rw);

	mem->write_phys<ia32::segment_descriptor_32>(gdt_pa + 0x00, {});
	mem->write_phys<ia32::segment_descriptor_32>(gdt_pa + 0x08, {});
	mem->write_phys(gdt_pa + 0x10, make_code_desc(0));
	mem->write_phys(gdt_pa + 0x18, make_data_desc(0));
	mem->write_phys<ia32::segment_descriptor_32>(gdt_pa + 0x20, {});
	mem->write_phys(gdt_pa + 0x28, make_data_desc(3));
	mem->write_phys(gdt_pa + 0x30, make_code_desc(3));
	mem->write_phys<ia32::segment_descriptor_32>(gdt_pa + 0x38, {});

	ia32::segment_descriptor_64 tss_desc{};
	tss_desc.base_address_low = static_cast<std::uint16_t>(tss_pa);
	tss_desc.base_address_middle = (tss_pa >> 16) & 0xFF;
	tss_desc.base_address_high = (tss_pa >> 24) & 0xFF;
	tss_desc.base_address_upper = static_cast<std::uint32_t>(tss_pa >> 32);
	tss_desc.segment_limit_low = static_cast<std::uint16_t>(tss_limit);
	tss_desc.type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
	tss_desc.present = 1;
	mem->write_phys(gdt_pa + 0x40, tss_desc);

	mem->write_phys<ia32::segment_descriptor_32>(gdt_pa + 0x50, {});

	constexpr std::size_t idt_size = 256 * sizeof(ia32::segment_descriptor_interrupt_gate_64);
	addr_t idt_pa = mem->alloc_phys(idt_size, prot_rw);

	cpu.reg(x86::gdtr, seg_reg{ 0, gdt_pa, static_cast<std::uint32_t>(gdt_size - 1), 0 });
	cpu.reg(x86::idtr, seg_reg{ 0, idt_pa, static_cast<std::uint32_t>(idt_size - 1), 0 });

	ia32::segment_access_rights tr_access{};
	tr_access.type = SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY;
	tr_access.present = 1;
	cpu.reg(x86::tr, seg_reg{ 0x40, tss_pa, tss_limit, tr_access.flags });

	ia32::segment_access_rights cs_access{};
	cs_access.type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
	cs_access.descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
	cs_access.present = 1;
	cs_access.long_mode = 1;
	cs_access.granularity = 1;
	cpu.reg(x86::cs, seg_reg{ 0x10, 0, 0xFFFFFFFF, cs_access.flags });

	ia32::segment_access_rights data_access{};
	data_access.type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
	data_access.descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
	data_access.present = 1;
	data_access.default_big = 1;
	data_access.granularity = 1;
	seg_reg data_sr{ 0x18, 0, 0xFFFFFFFF, data_access.flags };
	cpu.reg(x86::ss, data_sr);
	cpu.reg(x86::ds, data_sr);
	cpu.reg(x86::es, data_sr);
	cpu.reg(x86::fs, data_sr);
	cpu.reg(x86::gs, data_sr);

	cpu.reg(x86::ldtr, seg_reg{});
}

}
