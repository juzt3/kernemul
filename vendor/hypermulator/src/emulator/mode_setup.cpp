#include "emulator.hpp"
#include <ia32.hpp>
#include <intrin.h>
#include <spdlog/spdlog.h>

constexpr segment_selector cs_selector = { 0, 0, 1 };
constexpr segment_selector ds_selector = { 0, 0, 2 };

static cpuid_eax_01 query_cpuid_eax_01()
{
	cpuid_eax_01 cpu_info;

	__cpuid(reinterpret_cast<std::int32_t*>(&cpu_info), 1);

	return cpu_info;
}

static segment_descriptor_32 make_base_gdt_descriptor()
{
	constexpr std::uint32_t limit = 0xfffff;

	segment_descriptor_32 descriptor = { };

	descriptor.present = 1;
	descriptor.granularity = 1;
	descriptor.default_big = 1;
	descriptor.descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
	descriptor.segment_limit_low = limit & 0xFFFF;
	descriptor.segment_limit_high = (limit >> 16) & 0xF;

	return descriptor;
}

template <hm::reg_t Register>
static void set_table_register(hm::vcpu& cpu, const hm::addr_t base,
                               const std::size_t limit)
{
	const hm::table_reg table = {
		.pad = { },
		.limit = static_cast<std::uint16_t>(limit),
		.base = base
	};

	cpu.reg_write<Register>(table);
}

static bool set_up_gdt_descriptors(hm::partition& partition, hm::vcpu& cpu,
                                   const std::span<const segment_descriptor_32> descriptors)
{
	constexpr hm::addr_t gdt_base = 0x5000;
	constexpr hm::addr_t descriptors_base_address = gdt_base + sizeof(segment_descriptor_32);

	const std::size_t descriptors_size = descriptors.size() * sizeof(segment_descriptor_32);

	// to account for null entry, we add 1
	const std::size_t total_size = descriptors_size + sizeof(segment_descriptor_32);

	if (hm::partition::page_size < total_size ||
		!partition.map_phys_mem(gdt_base, hm::partition::page_size, hm::prot_rw) ||
		!partition.write_phys_mem(descriptors_base_address, descriptors.data(), descriptors_size))
	{
		return false;
	}

	set_table_register<hm::reg::gdtr>(cpu, gdt_base, total_size - 1);

	return true;
}

static void set_up_segments(hm::vcpu& cpu, const bool is_long, const bool uses_gdt)
{
	constexpr std::uint32_t segment_limit = 0xFFFFF;

	WHV_X64_SEGMENT_REGISTER segment = { };

	segment.Present = 1;
	segment.NonSystemSegment = 1;
	segment.Limit = segment_limit;

	segment.Selector = uses_gdt ? ds_selector.flags : 0;
	segment.SegmentType = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;

	cpu.reg_write<hm::reg::ss>(segment);
	cpu.reg_write<hm::reg::ds>(segment);
	cpu.reg_write<hm::reg::es>(segment);
	cpu.reg_write<hm::reg::fs>(segment);
	cpu.reg_write<hm::reg::gs>(segment);

	segment.Selector = uses_gdt ? cs_selector.flags : 0;
	segment.SegmentType = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
	segment.Long = is_long;

	cpu.reg_write<hm::reg::cs>(segment);
}

static void enable_ia32e_mode(hm::vcpu& cpu)
{
	ia32_efer_register efer = cpu.reg_read<hm::reg::efer, ia32_efer_register>();

	efer.ia32e_mode_enable = 1;

	cpu.reg_write<hm::reg::efer>(efer);
}

static void enable_execute_disable_bit(hm::vcpu& cpu)
{
	ia32_efer_register efer = cpu.reg_read<hm::reg::efer, ia32_efer_register>();

	efer.execute_disable_bit_enable = 1;

	cpu.reg_write<hm::reg::efer>(efer);
}

static void enable_protected_mode(hm::vcpu& cpu)
{
	cr0 current_cr0 = cpu.reg_read<hm::reg::cr0, cr0>();

	current_cr0.protection_enable = 1;

	cpu.reg_write<hm::reg::cr0>(current_cr0);
}

static void enable_paging(hm::vcpu& cpu)
{
	cr0 current_cr0 = cpu.reg_read<hm::reg::cr0, cr0>();

	current_cr0.paging_enable = 1;

	cpu.reg_write<hm::reg::cr0>(current_cr0);
}

static void enable_physical_address_extension(hm::vcpu& cpu)
{
	cr4 current_cr4 = cpu.reg_read<hm::reg::cr4, cr4>();

	current_cr4.physical_address_extension = 1;

	cpu.reg_write<hm::reg::cr4>(current_cr4);
}

static void enable_sse(hm::vcpu& cpu)
{
	cr4 current_cr4 = cpu.reg_read<hm::reg::cr4, cr4>();

	current_cr4.os_fxsave_fxrstor_support = 1;
	current_cr4.os_xmm_exception_support = 1;

	cpu.reg_write<hm::reg::cr4>(current_cr4);
}

static void enable_xsave(hm::vcpu& cpu)
{
	cr4 current_cr4 = cpu.reg_read<hm::reg::cr4, cr4>();

	current_cr4.os_xsave = 1;

	cpu.reg_write<hm::reg::cr4>(current_cr4);
}

static void set_up_general_purpose_registers(hm::vcpu& cpu)
{
	const cpuid_eax_01 cpu_info = query_cpuid_eax_01();
	const std::uint32_t extended_model_value = cpu_info.cpuid_version_information.extended_model_id;

	cpu.reg_write<hm::reg::rdx>((extended_model_value << 16) | 0x600);
	cpu.reg_write<hm::reg::rax>(0);
	cpu.reg_write<hm::reg::rbx>(0);
	cpu.reg_write<hm::reg::rcx>(0);
	cpu.reg_write<hm::reg::rsi>(0);
	cpu.reg_write<hm::reg::rdi>(0);
	cpu.reg_write<hm::reg::rbp>(0);
	cpu.reg_write<hm::reg::rsp>(0);
	cpu.reg_write<hm::reg::r8>(0);
	cpu.reg_write<hm::reg::r9>(0);
	cpu.reg_write<hm::reg::r10>(0);
	cpu.reg_write<hm::reg::r11>(0);
	cpu.reg_write<hm::reg::r12>(0);
	cpu.reg_write<hm::reg::r13>(0);
	cpu.reg_write<hm::reg::r14>(0);
	cpu.reg_write<hm::reg::r15>(0);
}

static void set_up_xmm_registers(hm::vcpu& cpu)
{
	cpu.reg_write<hm::reg::xmm0>(0);
	cpu.reg_write<hm::reg::xmm1>(0);
	cpu.reg_write<hm::reg::xmm2>(0);
	cpu.reg_write<hm::reg::xmm3>(0);
	cpu.reg_write<hm::reg::xmm4>(0);
	cpu.reg_write<hm::reg::xmm5>(0);
	cpu.reg_write<hm::reg::xmm6>(0);
	cpu.reg_write<hm::reg::xmm7>(0);
	cpu.reg_write<hm::reg::xmm8>(0);
	cpu.reg_write<hm::reg::xmm9>(0);
	cpu.reg_write<hm::reg::xmm10>(0);
	cpu.reg_write<hm::reg::xmm11>(0);
	cpu.reg_write<hm::reg::xmm12>(0);
	cpu.reg_write<hm::reg::xmm13>(0);
	cpu.reg_write<hm::reg::xmm14>(0);
	cpu.reg_write<hm::reg::xmm15>(0);
}

static void set_up_table_registers(hm::vcpu& cpu)
{
	set_table_register<hm::reg::gdtr>(cpu, 0, 0xFFFF);
	set_table_register<hm::reg::idtr>(cpu, 0, 0xFFFF);
}

static void set_up_debug_registers(hm::vcpu& cpu)
{
	cpu.reg_write<hm::reg::dr0>(0);
	cpu.reg_write<hm::reg::dr1>(0);
	cpu.reg_write<hm::reg::dr2>(0);
	cpu.reg_write<hm::reg::dr3>(0);
	cpu.reg_write<hm::reg::dr6>(0);
	cpu.reg_write<hm::reg::dr7>(0);
}

static void set_up_control_registers(hm::vcpu& cpu)
{
	cpu.reg_write<hm::reg::cr0>(0x60000010);
	cpu.reg_write<hm::reg::cr2>(0);
	cpu.reg_write<hm::reg::cr3>(0);
	cpu.reg_write<hm::reg::cr4>(0);
	cpu.reg_write<hm::reg::xcr0>(1);
}

static void cpu_init_state(hm::vcpu& cpu)
{
	// deviations for usability:
	// - base for CS segment should be 0xFFFF0000
	// - selector for CS segment should be 0xF000
	// - limit for (SS, DS, ES, FS, GS) segments should be 0xFFFF

	cpu.reg_write<hm::reg::rip>(0xFFF0);

	cpu.reg_write<hm::reg::rflags>(2);

	cpu.reg_write<hm::reg::efer>(0);

	set_up_control_registers(cpu);

	set_up_general_purpose_registers(cpu);
	set_up_xmm_registers(cpu);

	set_up_debug_registers(cpu);

	set_up_table_registers(cpu);

	set_up_segments(cpu, false, false);
}

bool hm::emu::load_cpu_mode_default_state()
{
	auto cpu = this->cpu();

	// mode_16
	cpu_init_state(cpu);

	if (mode_ != machine_mode_16) // mode_32, mode_64
	{
		enable_protected_mode(cpu);

		if (mode_ == machine_mode_64)
		{
			enable_paging(cpu);
			enable_physical_address_extension(cpu);

			enable_ia32e_mode(cpu);
			enable_execute_disable_bit(cpu);

			enable_sse(cpu);
			enable_xsave(cpu);
		}
	}

	return true;
}

bool hm::emu::create_default_gdt()
{
	const segment_descriptor_32 base_gdt_descriptor = make_base_gdt_descriptor();

	// 1 - kernel code segment descriptor
	// 2 - kernel data segment descriptor
	std::array gdt_descriptors = { base_gdt_descriptor, base_gdt_descriptor };

	gdt_descriptors[cs_selector.index - 1].type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
	gdt_descriptors[ds_selector.index - 1].type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;

	auto cpu = this->cpu();

	const bool is_long = mode_ == machine_mode_64;

	set_up_segments(cpu, is_long, true);

	return set_up_gdt_descriptors(*partition_, cpu, gdt_descriptors);
}

bool hm::emu::create_default_page_tables()
{
	constexpr hm::addr_t pml4_mapping = reserved_base + page_size;
	constexpr hm::addr_t pdpt_mapping = pml4_mapping + page_size;

	if (!map_phys_mem(pml4_mapping, page_size * 2, prot_rw))
	{
		return false;
	}

	constexpr std::size_t pte_count = 512;

	std::array<pml4e_64, pte_count> pml4 = { };
	std::array<pdpte_1gb_64, pte_count> pdpt = { };

	pml4e_64& pml4e = pml4[0];

	pml4e.present = 1;
	pml4e.write = 1;
	pml4e.page_frame_number = pdpt_mapping >> 12;

	for (std::uint64_t i = 0; i < pte_count; i++)
	{
		pdpte_1gb_64& pdpte = pdpt[i];

		pdpte.present = 1;
		pdpte.write = 1;
		pdpte.large_page = 1;
		pdpte.page_frame_number = i;
	}

	if (!write_phys_mem(pml4_mapping, pml4.data(), sizeof(pml4)) ||
		!write_phys_mem(pdpt_mapping, pdpt.data(), sizeof(pdpt)))
	{
		return false;
	}

	reg_write<reg::cr3>(pml4_mapping);

	return true;
}
