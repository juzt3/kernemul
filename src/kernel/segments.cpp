#include "segments.hpp"
#include "exception.hpp"
#include "../emulator/object.hpp"
#include "../impl/ntoskrnl/nt_helpers.hpp"
#include "kernel.hpp"

#include <ia32-doc/ia32.hpp>
#include "../util/logs.hpp"
#include <fstream>
#include <array>
#include <format>

constexpr std::uint16_t kernel_cs_selector = 2 * sizeof(segment_descriptor_32);
constexpr std::uint16_t kernel_ds_selector = 3 * sizeof(segment_descriptor_32);
constexpr std::uint16_t tss_selector_value = 8 * sizeof(segment_descriptor_32);

constexpr std::uint32_t segment_limit = 0xFFFFF;

constexpr std::uint16_t data_segment_attributes =
	SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED
	| (1 << 4)
	| (kernel::kernelmode_cpl << 5)
	| (1 << 7);

constexpr std::uint16_t code_segment_attributes =
	SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED
	| (1 << 4)
	| (kernel::kernelmode_cpl << 5)
	| (1 << 7)
	| (1 << 13);

constexpr std::uint16_t tss_attributes = 0x008B;

segment_descriptor_32 make_gdt_descriptor(const std::uint32_t privilege_level)
{
	segment_descriptor_32 descriptor = { };

	descriptor.present = 1;
	descriptor.granularity = 1;
	descriptor.descriptor_privilege_level = privilege_level;
	descriptor.descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
	descriptor.segment_limit_low = segment_limit & 0xFFFF;
	descriptor.segment_limit_high = (segment_limit >> 16) & 0xF;

	return descriptor;
}

segment_descriptor_32 make_code_gdt_descriptor(const std::uint32_t privilege_level, const bool is_long = true)
{
	auto descriptor = make_gdt_descriptor(privilege_level);

	descriptor.type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
	descriptor.long_mode = is_long;
	descriptor.default_big = !is_long;

	return descriptor;
}

segment_descriptor_32 make_data_gdt_descriptor(const std::uint32_t privilege_level)
{
	auto descriptor = make_gdt_descriptor(privilege_level);

	descriptor.type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
	descriptor.default_big = 1;

	return descriptor;
}

void kernel::set_up_segments(const std::shared_ptr<emulator_t>& emulator)
{
	auto error = emulator->write_segment(x86::segment_reg::cs, kernel_cs_selector, 0, segment_limit, code_segment_attributes);
	error.throw_if("write CS");

	error = emulator->write_segment(x86::segment_reg::ss, kernel_ds_selector, 0, segment_limit, data_segment_attributes);
	error.throw_if("write SS");

	error = emulator->write_segment(x86::segment_reg::ds, kernel_ds_selector, 0, segment_limit, data_segment_attributes);
	error.throw_if("write DS");

	error = emulator->write_segment(x86::segment_reg::es, kernel_ds_selector, 0, segment_limit, data_segment_attributes);
	error.throw_if("write ES");

	error = emulator->write_segment(x86::segment_reg::fs, kernel_ds_selector, 0, segment_limit, data_segment_attributes);
	error.throw_if("write FS");

	GLOBAL_LOG("configured segment registers: CS=0x{:X} SS/DS/ES/FS=0x{:X}", kernel_cs_selector, kernel_ds_selector);
}

void kernel::set_up_kernel_gs(const std::shared_ptr<emulator_t>& emulator, const emulator_t::address_type kpcr_address)
{
	const emulator_err_t error = emulator->write_segment(
		x86::segment_reg::gs, kernel_ds_selector, kpcr_address, segment_limit, data_segment_attributes);

	error.throw_if("write kernel gs segment");

	GLOBAL_LOG("mapped kernel gs at 0x{:X}", kpcr_address);
}

void kernel::set_up_gdt(const std::shared_ptr<emulator_t>& emulator)
{
	constexpr segment_descriptor_32 null_descriptor = { };

	const auto tss_allocation = emulator->heap_allocate(sizeof(task_state_segment_64), prot_read_write, true);

	emulator_err_t error = tss_allocation.error_or({});
	error.throw_if("allocate TSS");

	const auto tss_address = *tss_allocation;

	task_state_segment_64 tss = { };
	tss.rsp0 = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

	error = emulator->write_virtual_memory(tss_address, &tss, sizeof(tss));
	error.throw_if("write TSS");

	constexpr std::uint32_t tss_limit = sizeof(task_state_segment_64) - 1;

	segment_descriptor_64 tss_descriptor = { };
	tss_descriptor.segment_limit_low = tss_limit & 0xFFFF;
	tss_descriptor.segment_limit_high = (tss_limit >> 16) & 0xF;
	tss_descriptor.base_address_low = tss_address & 0xFFFF;
	tss_descriptor.base_address_middle = (tss_address >> 16) & 0xFF;
	tss_descriptor.base_address_high = (tss_address >> 24) & 0xFF;
	tss_descriptor.base_address_upper = static_cast<std::uint32_t>(tss_address >> 32);
	tss_descriptor.type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
	tss_descriptor.present = 1;

	segment_descriptor_32 tss_slots[2] = { };
	std::memcpy(tss_slots, &tss_descriptor, sizeof(tss_descriptor));

	std::array gdt_entries = {
		null_descriptor,                               // 0: null
		null_descriptor,                               // 1: reserved
		make_code_gdt_descriptor(kernelmode_cpl),          // 2: kernel CS (selector 0x10)
		make_data_gdt_descriptor(kernelmode_cpl),          // 3: kernel DS (selector 0x18)
		null_descriptor,                                             // 4: reserved (contains similar to user CS)
		make_data_gdt_descriptor(usermode_cpl),        // 5: user DS
		make_code_gdt_descriptor(usermode_cpl, false), // 6: user CS (compat)
		null_descriptor,                               // 7: reserved
		tss_slots[0],                                  // 8: TSS64 (low)
		tss_slots[1],                                  // 9: TSS64 (high)
		null_descriptor                    // 10: reserved (contains similar to user DS)
	};

	constexpr emulator_t::size_type gdt_size = sizeof(gdt_entries);

	const auto gdt_allocation = emulator->heap_allocate(gdt_size, prot_read_write, true);
	error = gdt_allocation.error_or({});
	error.throw_if("allocate GDT");

	const auto gdt_base = *gdt_allocation;

	error = emulator->write_virtual_memory(gdt_base, gdt_entries.data(), gdt_size);
	error.throw_if("write GDT entries");

	error = emulator->write_gdt(gdt_base, gdt_size - 1);
	error.throw_if("load GDTR");

	error = emulator->write_tr(tss_selector_value, tss_address, tss_limit, tss_attributes);
	error.throw_if("load TR");

	GLOBAL_LOG("mapped GDT at 0x{:X} ({} entries), TSS at 0x{:X}, TR selector=0x{:X}",
		gdt_base, gdt_entries.size(), tss_address, tss_selector_value);
}

void kernel::set_up_idt(const std::shared_ptr<emulator_t>& emulator, const kernel_image_t& nt_image)
{
	constexpr std::uint32_t handler_count = 256;
	constexpr emulator_t::size_type idt_size = handler_count * sizeof(segment_descriptor_interrupt_gate_64);
	constexpr emulator_t::size_type handler_stride = 0x10;

	const auto idt_base_address = emulator->heap_allocate(idt_size, prot_read_write, true);

	emulator_err_t error = idt_base_address.error_or({});
	error.throw_if("map IDT");

	const auto handler_base = nt_image.base_address() + 0x404630;
	
	for (std::uint32_t i = 0; i < handler_count; i++)
	{
		const auto handler_address = handler_base + i * handler_stride;

		constexpr std::array<std::uint32_t, 10> error_code_handlers = {
			8, 10, 11,
			12, 13, 14,
			17, 21, 29,
			30
		};

		const bool has_error_code = std::ranges::contains(error_code_handlers, i);

		redirected_functions[handler_address] = [emulator, i, has_error_code](bool& skip_return)
			{
				skip_return = true;

				auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

				std::uint64_t error_code = 0;

				if (has_error_code)
				{
					const auto error = emulator->read_virtual_memory(rsp, &error_code, sizeof(error_code));
					error.throw_if("read interrupt error code");
					rsp += 8;
				}

				struct interrupt_frame
				{
					std::uint64_t rip;
					std::uint64_t cs;
					std::uint64_t rflags;
					std::uint64_t rsp;
					std::uint64_t ss;
				};

				interrupt_frame frame = { };
				emulator_err_t error = emulator->read_virtual_memory(rsp, &frame, sizeof(frame));
				error.throw_if("read interrupt frame");

				if (has_error_code)
				{
					THREAD_LOG("interrupt vector 0x{:X} (error_code=0x{:X}): rip=0x{:X} cs=0x{:X} rflags=0x{:X} rsp=0x{:X} ss=0x{:X}",
						i, error_code, frame.rip, frame.cs, frame.rflags, frame.rsp, frame.ss);
				}
				else
				{
					THREAD_LOG("interrupt vector 0x{:X}: rip=0x{:X} cs=0x{:X} rflags=0x{:X} rsp=0x{:X} ss=0x{:X}",
						i, frame.rip, frame.cs, frame.rflags, frame.rsp, frame.ss);
				}

				emulator->write_register<x86::reg::rip>(frame.rip);
				emulator->write_register<x86::reg::rsp>(frame.rsp);
				emulator->write_register<x86::reg::rflags>(frame.rflags);

				constexpr std::uint32_t status_integer_divide_by_zero = 0xC0000094;
				constexpr std::uint32_t status_single_step = 0x80000004;
				constexpr std::uint32_t status_breakpoint = 0x80000003;
				constexpr std::uint32_t status_array_bounds_exceeded = 0xC000008C;
				constexpr std::uint32_t status_illegal_instruction = 0xC000001D;
				constexpr std::uint32_t status_access_violation = 0xC0000005;

				std::array<std::uint8_t, 2> instruction_bytes = { };

				error = emulator->read_virtual_memory(frame.rip, instruction_bytes);

				if (!error)
				{
					if (instruction_bytes[0] == 0x0F && instruction_bytes[1] == 0x32) // rdmsr
					{
						const auto msr_id = emulator->read_register<x86::reg::rcx, std::uint32_t>();

						if (msr_id == 0x1C9 || msr_id == 0x680)
						{
							THREAD_LOG("MSR read with id 0x{:X}", msr_id);

							emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(0));
							emulator->write_register<x86::reg::rdx>(static_cast<std::uint64_t>(0));
							emulator->write_register<x86::reg::rip>(frame.rip + 2);

							return;
						}

						THREAD_WARN_LOG("invalid MSR read with id 0x{:X}", msr_id);
					}
					else if (instruction_bytes[0] == 0x0F && instruction_bytes[1] == 0x30) // wrmsr
					{
						const auto msr_id = emulator->read_register<x86::reg::rcx, std::uint32_t>();

						THREAD_WARN_LOG("invalid MSR write with id 0x{:X}", msr_id);
					}
				}

				switch (i)
				{
				case 0:
					handle_exception(emulator, frame.rip, status_integer_divide_by_zero, frame.rip);
					break;
				case 1:
					handle_exception(emulator, frame.rip, status_single_step, frame.rip);
					break;
				case 3:
					handle_exception(emulator, frame.rip, status_breakpoint, frame.rip);
					break;
				case 5:
					handle_exception(emulator, frame.rip, status_array_bounds_exceeded, frame.rip);
					break;
				case 6:
					handle_exception(emulator, frame.rip, status_illegal_instruction, frame.rip);
					break;
				case 13:
					handle_exception(emulator, frame.rip, status_access_violation, frame.rip);
					break;
				case 14:
				{
					const auto cr2 = emulator->read_register<x86::reg::cr2, emulator_t::address_type>();
					handle_exception(emulator, frame.rip, status_access_violation, cr2);
					break;
				}
				case 17:
					handle_exception(emulator, frame.rip, status_access_violation, frame.rip);
					break;
				default:
					THREAD_WARN_LOG("unhandled interrupt vector 0x{:X} at rip=0x{:X}", i, frame.rip);
					break;
				}
			};

		const std::uint32_t offset = i * sizeof(segment_descriptor_interrupt_gate_64);
		const std::string name = std::format("IDT vector #{:X}", i);

		auto entry_object = emulator_object_t<segment_descriptor_interrupt_gate_64>::view_at(emulator, *idt_base_address + offset, name);

		segment_descriptor_interrupt_gate_64 contents = { };

		contents.present = 1;
		contents.segment_selector = kernel_cs_selector;
		contents.type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;

		contents.offset_low = handler_address & 0xFFFF;
		contents.offset_middle = (handler_address >> 16) & 0xFFFF;
		contents.offset_high = (handler_address >> 32) & 0xFFFF'FFFF;

		entry_object.write(contents);
	}

	error = emulator->write_idt(*idt_base_address, idt_size - 1);
	error.throw_if("load IDT");

	GLOBAL_LOG("mapped IDT at 0x{:X}", *idt_base_address);
}
