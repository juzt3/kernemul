#include "segments.hpp"
#include "../../emu/mmu.hpp"

namespace ia32 {
#include <ia32.hpp>
}

namespace x86_win_seg
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

static x86::seg_reg make_code_sr(std::uint16_t selector, std::uint32_t dpl)
{
	ia32::segment_access_rights ar{};
	ar.type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
	ar.descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
	ar.descriptor_privilege_level = dpl;
	ar.present = 1;
	ar.long_mode = 1;
	ar.granularity = 1;
	return { selector, 0, 0xFFFFFFFF, ar.flags };
}

static x86::seg_reg make_data_sr(std::uint16_t selector, std::uint32_t dpl, std::uint64_t base = 0)
{
	ia32::segment_access_rights ar{};
	ar.type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
	ar.descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
	ar.descriptor_privilege_level = dpl;
	ar.present = 1;
	ar.default_big = 1;
	ar.granularity = 1;
	return { selector, base, 0xFFFFFFFF, ar.flags };
}

void init_vcpu(vcpu& cpu)
{
	auto* mem = cpu.emu()->mem().get();

	constexpr std::uint32_t tss_limit = 103;
	addr_t tss_pa = mem->alloc_phys(tss_limit + 1, prot_rw);

	constexpr std::size_t gdt_entries = 11;
	constexpr std::size_t gdt_size = gdt_entries * sizeof(ia32::segment_descriptor_32);
	addr_t gdt_pa = mem->alloc_phys(gdt_size, prot_rw);

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

	cpu.reg(x86::gdtr, x86::seg_reg{ 0, gdt_pa, static_cast<std::uint32_t>(gdt_size - 1), 0 });
	cpu.reg(x86::idtr, x86::seg_reg{ 0, idt_pa, static_cast<std::uint32_t>(idt_size - 1), 0 });

	ia32::segment_access_rights tr_access{};
	tr_access.type = SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY;
	tr_access.present = 1;
	cpu.reg(x86::tr, x86::seg_reg{ tss_sel, tss_pa, tss_limit, tr_access.flags });

	cpu.reg(x86::cs, make_code_sr(kernel_cs, 0));

	auto data_sr = make_data_sr(kernel_ds, 0);
	cpu.reg(x86::ss, data_sr);
	cpu.reg(x86::ds, data_sr);
	cpu.reg(x86::es, data_sr);
	cpu.reg(x86::fs, data_sr);
	cpu.reg(x86::gs, data_sr);

	cpu.reg(x86::ldtr, x86::seg_reg{});
}

void set_kernel_gs(vcpu& cpu, const std::uint64_t base)
{
	cpu.reg(x86::gs, make_data_sr(kernel_ds, 0, base));
}

void set_usermode_gs(vcpu& cpu, const std::uint64_t teb_addr)
{
	cpu.reg(x86::gs, make_data_sr(user_ds, 3, teb_addr));
}

void swap_to_kernel_segments(vcpu& cpu)
{
	cpu.reg(x86::cs, make_code_sr(kernel_cs, 0));
	cpu.reg(x86::ss, make_data_sr(kernel_ds, 0));
}

void swap_to_usermode_segments(vcpu& cpu)
{
	cpu.reg(x86::cs, make_code_sr(user_cs, 3));
	cpu.reg(x86::ss, make_data_sr(user_ds, 3));
}

}
