#include "segments.hpp"
#include <array>
#include "../../emu/mmu.hpp"
#include "../../emu/object.hpp"
#include "../process.hpp"

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

// The gate a vector carries is the handler ntoskrnl really installs there. Nothing here
// dispatches through the table, but guest code reads it back and follows what it finds.
struct ki_vector
{
	std::uint8_t vector;
	std::string_view name;
};

constexpr ki_vector ki_vectors[] = {
	{  0, "KiDivideErrorFault" },        {  1, "KiDebugTrapOrFault" },
	{  2, "KiNmiInterrupt" },            {  3, "KiBreakpointTrap" },
	{  4, "KiOverflowTrap" },            {  5, "KiBoundFault" },
	{  6, "KiInvalidOpcodeFault" },      {  7, "KiNpxNotAvailableFault" },
	{  8, "KiDoubleFaultAbort" },        {  9, "KiNpxSegmentOverrunAbort" },
	{ 10, "KiInvalidTssFault" },         { 11, "KiSegmentNotPresentFault" },
	{ 12, "KiStackFault" },              { 13, "KiGeneralProtectionFault" },
	{ 14, "KiPageFault" },               { 16, "KiFloatingErrorFault" },
	{ 17, "KiAlignmentFault" },          { 18, "KiMcheckAbort" },
	{ 19, "KiXmmException" },            { 20, "KiVirtualizationException" },
	{ 21, "KiControlProtectionFault" },  { 29, "KiRaiseSecurityCheckFailure" },
	{ 44, "KiRaiseAssertion" },          { 45, "KiDebugServiceTrap" },
};

static addr_t init_idt(vcpu& cpu, const proc_module& ntoskrnl)
{
	auto* space = cpu.curr_addr_space().get();

	constexpr std::size_t idt_entries = 256;
	constexpr std::size_t idt_size = idt_entries * sizeof(ia32::segment_descriptor_interrupt_gate_64);
	const addr_t idt_va = space->alloc(idt_size, prot_rw | prot_supervisor);

	std::array<addr_t, idt_entries> handlers{};

	for (const auto& [vector, name] : ki_vectors)
	{
		if (const auto addr = ntoskrnl.find_symbol(name))
			handlers[vector] = *addr;
	}

	// Every vector the kernel does not name gets a stub of its own rather than one shared
	// address. A table read back then holds 256 different handlers, each a few bytes into a
	// neighbouring run -- which is the shape a real one has, where the reserved vectors are all
	// served by a block of stubs that differ only in where they sit.
	constexpr std::size_t stub_stride = 16;
	const addr_t stubs = space->alloc(idt_entries * stub_stride, prot_rx | prot_supervisor);

	std::array<std::uint8_t, stub_stride> stub{};
	stub[0] = 0x48; // iretq
	stub[1] = 0xCF;

	for (std::size_t i = 2; i < stub_stride; ++i)
		stub[i] = 0x90; // nop

	for (std::size_t i = 0; i < idt_entries; ++i)
		space->write_mem(stubs + i * stub_stride, stub.data(), stub.size());

	// int3, into and the two debug-service vectors are the ones a user can reach directly, so
	// their gates carry ring 3 in the privilege field and the rest carry ring 0.
	const auto user_callable = [](const std::size_t vector)
	{
		return vector == 3 || vector == 4 || vector == 45 || vector == 46;
	};

	std::size_t named = 0;

	for (std::size_t i = 0; i < idt_entries; ++i)
	{
		const auto handler = handlers[i] ? handlers[i] : stubs + i * stub_stride;

		ia32::segment_descriptor_interrupt_gate_64 gate{};
		gate.offset_low    = static_cast<std::uint16_t>(handler);
		gate.segment_selector = kernel_cs;
		gate.type          = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;
		gate.present       = 1;
		gate.descriptor_privilege_level = user_callable(i) ? 3 : 0;
		gate.offset_middle = static_cast<std::uint16_t>(handler >> 16);
		gate.offset_high   = static_cast<std::uint32_t>(handler >> 32);

		space->write_mem(idt_va + i * sizeof(gate), gate);

		if (handlers[i])
			++named;
	}

	cpu.reg(x86::idtr, x86::seg_reg{ 0, idt_va, static_cast<std::uint32_t>(idt_size - 1), 0 });

	monitor_range(*space, idt_va, idt_size, "IDT");

	LOG_INFO("IDT at 0x{:X}: {} named of 256 vectors, the other {} at their own stub from 0x{:X}",
		idt_va, named, idt_entries - named, stubs);

	return idt_va;
}

cpu_tables init_vcpu(vcpu& cpu, const proc_module& ntoskrnl)
{
	auto space = cpu.curr_addr_space();

	constexpr std::uint32_t tss_limit = 103;
	addr_t tss_va = space->alloc(tss_limit + 1, prot_rw | prot_supervisor);

	constexpr std::size_t gdt_entries = 11;
	constexpr std::size_t gdt_size = gdt_entries * sizeof(ia32::segment_descriptor_32);
	addr_t gdt_va = space->alloc(gdt_size, prot_rw | prot_supervisor);

	space->write_mem<ia32::segment_descriptor_32>(gdt_va + 0x00, {});
	space->write_mem<ia32::segment_descriptor_32>(gdt_va + 0x08, {});
	space->write_mem(gdt_va + 0x10, make_code_desc(0));
	space->write_mem(gdt_va + 0x18, make_data_desc(0));
	space->write_mem<ia32::segment_descriptor_32>(gdt_va + 0x20, {});
	space->write_mem(gdt_va + 0x28, make_data_desc(3));
	space->write_mem(gdt_va + 0x30, make_code_desc(3));
	space->write_mem<ia32::segment_descriptor_32>(gdt_va + 0x38, {});

	ia32::segment_descriptor_64 tss_desc{};
	tss_desc.base_address_low = static_cast<std::uint16_t>(tss_va);
	tss_desc.base_address_middle = (tss_va >> 16) & 0xFF;
	tss_desc.base_address_high = (tss_va >> 24) & 0xFF;
	tss_desc.base_address_upper = static_cast<std::uint32_t>(tss_va >> 32);
	tss_desc.segment_limit_low = static_cast<std::uint16_t>(tss_limit);
	tss_desc.type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
	tss_desc.present = 1;
	space->write_mem(gdt_va + 0x40, tss_desc);

	space->write_mem<ia32::segment_descriptor_32>(gdt_va + 0x50, {});

	cpu.reg(x86::gdtr, x86::seg_reg{ 0, gdt_va, static_cast<std::uint32_t>(gdt_size - 1), 0 });

	monitor_range(*space, gdt_va, gdt_size, "GDT");
	monitor_range(*space, tss_va, tss_limit + 1, "TSS");

	ia32::segment_access_rights tr_access{};
	tr_access.type = SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY;
	tr_access.present = 1;
	cpu.reg(x86::tr, x86::seg_reg{ tss_sel, tss_va, tss_limit, tr_access.flags });

	cpu.reg(x86::cs, make_code_sr(kernel_cs, 0));

	auto data_sr = make_data_sr(kernel_ds, 0);
	cpu.reg(x86::ss, data_sr);
	cpu.reg(x86::ds, data_sr);
	cpu.reg(x86::es, data_sr);
	cpu.reg(x86::fs, data_sr);
	cpu.reg(x86::gs, data_sr);

	cpu.reg(x86::ldtr, x86::seg_reg{});

	return { gdt_va, tss_va, init_idt(cpu, ntoskrnl) };
}

void set_kernel_gs(vcpu& cpu, const std::uint64_t base)
{
	cpu.reg(x86::gs, make_data_sr(kernel_ds, 0, base));
}

x86::seg_reg make_usermode_gs(const std::uint64_t teb_addr)
{
	return make_data_sr(user_ds, 3, teb_addr);
}

void set_usermode_gs(vcpu& cpu, const std::uint64_t teb_addr)
{
	cpu.reg(x86::gs, make_usermode_gs(teb_addr));
}

void swap_to_kernel_segments(vcpu& cpu)
{
	cpu.reg(x86::cs, make_code_sr(kernel_cs, 0));
	cpu.reg(x86::ss, make_data_sr(kernel_ds, 0));
}

x86::seg_reg make_usermode_cs()
{
	return make_code_sr(user_cs, 3);
}

x86::seg_reg make_usermode_ss()
{
	return make_data_sr(user_ds, 3);
}

void swap_to_usermode_segments(vcpu& cpu)
{
	cpu.reg(x86::cs, make_usermode_cs());
	cpu.reg(x86::ss, make_usermode_ss());
}

}
