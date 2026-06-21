#include "segments.hpp"
#include "exception.hpp"
#include "exception_common.hpp"
#include "../emulator/object.hpp"
#include "../impl/ntoskrnl/nt_helpers.hpp"
#include "kernel.hpp"
#include "../user/user_memory.hpp"
#include "../user/exception_dispatch.hpp"

#include <ia32-doc/ia32.hpp>
#include "../util/logs.hpp"
#include <fstream>
#include <array>
#include <format>

constexpr std::uint16_t tss_selector_value = 8 * sizeof(segment_descriptor_32);

constexpr std::uint16_t data_segment_attributes =
	SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED
	| (1 << 4)
	| (kernel::kernelmode_cpl << 5)
	| (1 << 7);

constexpr std::uint16_t user_data_segment_attributes =
	SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED
	| (1 << 4)
	| (kernel::usermode_cpl << 5)
	| (1 << 7);

constexpr std::uint16_t code_segment_attributes =
	SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED
	| (1 << 4)
	| (kernel::kernelmode_cpl << 5)
	| (1 << 7)
	| (1 << 13);

constexpr std::uint16_t user_code_segment_attributes =
	SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED
	| (1 << 4)
	| (kernel::usermode_cpl << 5)
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
	descriptor.segment_limit_low = kernel::segment_limit & 0xFFFF;
	descriptor.segment_limit_high = (kernel::segment_limit >> 16) & 0xF;

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
	auto error = emulator->write_segment(x86::segment_reg::cs, kernel_cs_selector, 0, kernel::segment_limit, code_segment_attributes);
	error.throw_if("write CS");

	error = emulator->write_segment(x86::segment_reg::ss, kernel_ds_selector, 0, kernel::segment_limit, data_segment_attributes);
	error.throw_if("write SS");

	error = emulator->write_segment(x86::segment_reg::ds, kernel_ds_selector, 0, kernel::segment_limit, data_segment_attributes);
	error.throw_if("write DS");

	error = emulator->write_segment(x86::segment_reg::es, kernel_ds_selector, 0, kernel::segment_limit, data_segment_attributes);
	error.throw_if("write ES");

	error = emulator->write_segment(x86::segment_reg::fs, kernel_ds_selector, 0, kernel::segment_limit, data_segment_attributes);
	error.throw_if("write FS");

	GLOBAL_LOG("configured segment registers: CS=0x{:X} SS/DS/ES/FS=0x{:X}", kernel_cs_selector, kernel_ds_selector);
}

void kernel::set_up_kernel_gs(const std::shared_ptr<emulator_t>& emulator, const emulator_t::address_type kpcr_address)
{
	const emulator_err_t error = emulator->write_segment(
		x86::segment_reg::gs, kernel_ds_selector, kpcr_address, kernel::segment_limit, data_segment_attributes);

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
		make_code_gdt_descriptor(usermode_cpl, true),  // 6: user CS (64-bit)
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

void kernel::set_up_idt(const std::shared_ptr<emulator_t>& emulator, const image_t& nt_image)
{
	constexpr std::uint32_t handler_count = 256;
	constexpr emulator_t::size_type idt_size = handler_count * sizeof(segment_descriptor_interrupt_gate_64);

	const auto idt_base_address = emulator->heap_allocate(idt_size, prot_read_write, true);

	emulator_err_t error = idt_base_address.error_or({});
	error.throw_if("map IDT");

	// resolve Ki* interrupt handler symbols from ntoskrnl PDB
	struct ki_entry { std::uint32_t vector; const char* name; };

	static constexpr ki_entry ki_symbols[] = {
		{ 0, "KiDivideErrorFault" }, { 1, "KiDebugTrapOrFault" },
		{ 2, "KiNmiInterrupt" }, { 3, "KiBreakpointTrap" },
		{ 4, "KiOverflowTrap" }, { 5, "KiBoundFault" },
		{ 6, "KiInvalidOpcodeFault" }, { 7, "KiNpxNotAvailableFault" },
		{ 8, "KiDoubleFaultAbort" }, { 9, "KiNpxSegmentOverrunAbort" },
		{ 10, "KiInvalidTssFault" }, { 11, "KiSegmentNotPresentFault" },
		{ 12, "KiStackFault" }, { 13, "KiGeneralProtectionFault" },
		{ 14, "KiPageFault" }, { 16, "KiFloatingErrorFault" },
		{ 17, "KiAlignmentFault" }, { 18, "KiMcheckAbort" },
		{ 19, "KiXmmException" }, { 20, "KiVirtualizationException" },
		{ 21, "KiControlProtectionFault" }, { 29, "KiRaiseSecurityCheckFailure" },
		{ 44, "KiRaiseAssertion" }, { 45, "KiDebugServiceTrap" },
	};

	std::unordered_map<std::uint32_t, emulator_t::address_type> ki_addresses;
	std::uint32_t ki_resolved = 0;

	for (const auto& [vector, name] : ki_symbols)
	{
		if (const auto addr = nt_image.find_symbol(name))
		{
			ki_addresses[vector] = *addr;
			++ki_resolved;
		}
	}

	// compute fallback base from end of ntoskrnl .text section
	const auto image_buffer = nt_image.buffer();
	const auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_buffer.data());
	const auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image_buffer.data() + dos_header->e_lfanew);
	const auto sections = IMAGE_FIRST_SECTION(nt_headers);

	emulator_t::address_type fallback_base = nt_image.base_address();

	for (std::uint16_t s = 0; s < nt_headers->FileHeader.NumberOfSections; ++s)
	{
		if (sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			const auto section_end = nt_image.base_address() + sections[s].VirtualAddress + sections[s].Misc.VirtualSize;
			fallback_base = section_end - handler_count * 16;
			break;
		}
	}

	GLOBAL_LOG("IDT handler resolution: {} Ki* symbols resolved, {} fallback (base=0x{:X})",
		ki_resolved, handler_count - ki_resolved, fallback_base);

	for (std::uint32_t i = 0; i < handler_count; i++)
	{
		emulator_t::address_type handler_address;

		if (const auto it = ki_addresses.find(i); it != ki_addresses.end())
		{
			handler_address = it->second;
		}
		else
		{
			handler_address = fallback_base + (i * 16);
		}

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

				exception_common::interrupt_frame_t frame = { };
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

				const bool is_usermode = (frame.cs & 3) == 3;
				const auto exception_code = exception_common::vector_to_exception_code(i);

				auto fault_address = static_cast<emulator_t::address_type>(frame.rip);

				if (i == 14)
				{
					fault_address = emulator->read_register<x86::reg::cr2, emulator_t::address_type>();
				}

				if (is_usermode && kernel::current_thread
					&& kernel::current_thread->process()->ki_user_exception_dispatcher())
				{
					if (exception_code)
					{
						THREAD_LOG("exception dispatch: code=0x{:X}, rip=0x{:X}, faulting_address=0x{:X}",
							exception_code, frame.rip, fault_address);

						if (i == 14)
						{
							const bool is_write = (error_code & 2) != 0;
							user::dispatch_access_violation(emulator, fault_address, is_write);
						}
						else
						{
							user::dispatch_exception(emulator, exception_code, fault_address, nullptr, 0);
						}
					}
					else
					{
						THREAD_WARN_LOG("unhandled usermode interrupt vector 0x{:X} at rip=0x{:X}", i, frame.rip);
					}
				}
				else
				{
					if (exception_code)
					{
						if (i == 1)
						{
							const bool handled = handle_exception(emulator, frame.rip, exception_code, frame.rip, true);

							if (!handled)
							{
								emulator->write_register<x86::reg::rip>(frame.rip);
								emulator->write_register<x86::reg::rsp>(frame.rsp);
								emulator->write_register<x86::reg::rflags>(frame.rflags & ~static_cast<std::uint64_t>(0x100));
							}
						}
						else
						{
							handle_exception(emulator, frame.rip, exception_code, fault_address);
						}
					}
					else
					{
						THREAD_WARN_LOG("unhandled interrupt vector 0x{:X} at rip=0x{:X}", i, frame.rip);
					}
				}
			};

		const std::uint32_t offset = i * sizeof(segment_descriptor_interrupt_gate_64);
		const std::string name = std::format("IDT vector #{:X}", i);

		auto entry_object = emulator_object_t<segment_descriptor_interrupt_gate_64>::view_at(emulator, *idt_base_address + offset, name, false);

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
}

void kernel::swap_to_kernel_gs(const std::shared_ptr<emulator_t>& emulator)
{
	const emulator_err_t error = emulator->write_segment(
		x86::segment_reg::gs, kernel_ds_selector, kpcr_address, kernel::segment_limit, data_segment_attributes);

	error.throw_if("swap to kernel gs");
}

void kernel::swap_to_usermode_gs(const std::shared_ptr<emulator_t>& emulator,
                                 const emulator_t::address_type teb_address)
{
	const emulator_err_t error = emulator->write_segment(
		x86::segment_reg::gs, user_ds_selector, teb_address, kernel::segment_limit, user_data_segment_attributes);

	error.throw_if("swap to usermode gs");
}

void kernel::swap_to_kernel_segments(const std::shared_ptr<emulator_t>& emulator)
{
	auto error = emulator->write_segment(
		x86::segment_reg::cs, kernel_cs_selector, 0, kernel::segment_limit, code_segment_attributes);
	error.throw_if("swap to kernel cs");

	error = emulator->write_segment(
		x86::segment_reg::ss, kernel_ds_selector, 0, kernel::segment_limit, data_segment_attributes);
	error.throw_if("swap to kernel ss");
}

void kernel::swap_to_usermode_segments(const std::shared_ptr<emulator_t>& emulator)
{
	auto error = emulator->write_segment(
		x86::segment_reg::cs, user_cs_selector, 0, kernel::segment_limit, user_code_segment_attributes);
	error.throw_if("swap to usermode cs");

	error = emulator->write_segment(
		x86::segment_reg::ss, user_ds_selector, 0, kernel::segment_limit, user_data_segment_attributes);
	error.throw_if("swap to usermode ss");
}
