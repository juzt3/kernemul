#include "nt_helpers.hpp"

constexpr std::uint32_t dump_signature = 0x45474150;
constexpr std::uint32_t dump_valid_dump = 0x34365544;
constexpr std::uint32_t dump_end_signature = 0x444D5054;
constexpr std::uint32_t machine_amd64 = 34404;
constexpr std::uint32_t dump_buffer_size = 0x40000;

void redirect_ntoskrnl_crashdump_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			const auto context_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto thread_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto bugcheck_code = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto bugcheck_param1 = emulator->read_register<x86::reg::r9, std::uint64_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			std::uint64_t bugcheck_param2 = 0;
			std::uint64_t bugcheck_param3 = 0;
			std::uint64_t bugcheck_param4 = 0;
			emulator_t::address_type output_address = 0;

			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &bugcheck_param2, sizeof(bugcheck_param2)));
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &bugcheck_param3, sizeof(bugcheck_param3)));
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &bugcheck_param4, sizeof(bugcheck_param4)));
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x40, &output_address, sizeof(output_address)));

			THREAD_LOG("KeCapturePersistentThreadState called (context=0x{:X}, thread=0x{:X}, bugcheck=0x{:X}, "
				"p1=0x{:X}, p2=0x{:X}, p3=0x{:X}, p4=0x{:X}, output=0x{:X})",
				context_address, thread_address, bugcheck_code,
				bugcheck_param1, bugcheck_param2, bugcheck_param3, bugcheck_param4, output_address);

			if (!output_address)
			{
				write_return_value(emulator, 0);
				return;
			}

			auto current_thread = thread_address;

			if (!current_thread)
			{
				current_thread = kernel::current_thread->address();
			}

			std::vector<std::uint8_t> buffer(dump_buffer_size, 0);
			auto* buf = buffer.data();

			std::memset(buf + 8, 0, 0x3FFF8);

			*reinterpret_cast<std::uint32_t*>(buf + 0) = dump_signature;
			*reinterpret_cast<std::uint32_t*>(buf + 4) = dump_valid_dump;

			constexpr std::uint32_t nt_build_number = 26100;
			*reinterpret_cast<std::uint32_t*>(buf + 8) = 0;
			*reinterpret_cast<std::uint32_t*>(buf + 12) = nt_build_number;

			emulator_t::address_type process_address = 0;
			static_cast<void>(emulator->read_virtual_memory(
				current_thread + offsetof(_KTHREAD, ApcState) + offsetof(_KAPC_STATE, Process),
				&process_address, sizeof(process_address)));

			if (process_address)
			{
				std::uint64_t dtb = 0;
				static_cast<void>(emulator->read_virtual_memory(
					process_address + offsetof(_KPROCESS, DirectoryTableBase),
					&dtb, sizeof(dtb)));

				*reinterpret_cast<std::uint64_t*>(buf + 16) = dtb & 0xFFFFFFFFFFFFF000ull;
			}

			if (const auto ntoskrnl = kernel::find_module("ntoskrnl.exe"))
			{
				if (const auto pfn_db = ntoskrnl->find_symbol("MmPfnDatabase"))
				{
					std::uint64_t pfn_value = 0;
					static_cast<void>(emulator->read_virtual_memory(*pfn_db, &pfn_value, sizeof(pfn_value)));
					*reinterpret_cast<std::uint64_t*>(buf + 24) = pfn_value;
				}

				if (const auto ps_module_list = ntoskrnl->find_symbol("PsLoadedModuleList"))
				{
					*reinterpret_cast<std::uint64_t*>(buf + 32) = *ps_module_list;
				}

				if (const auto ps_active_head = ntoskrnl->find_symbol("PsActiveProcessHead"))
				{
					*reinterpret_cast<std::uint64_t*>(buf + 40) = *ps_active_head;
				}
			}

			*reinterpret_cast<std::uint32_t*>(buf + 48) = machine_amd64;
			*reinterpret_cast<std::uint32_t*>(buf + 52) = 1;

			*reinterpret_cast<std::uint32_t*>(buf + 56) = bugcheck_code;
			*reinterpret_cast<std::uint64_t*>(buf + 64) = bugcheck_param1;
			*reinterpret_cast<std::uint64_t*>(buf + 72) = bugcheck_param2;
			*reinterpret_cast<std::uint64_t*>(buf + 80) = bugcheck_param3;
			*reinterpret_cast<std::uint64_t*>(buf + 88) = bugcheck_param4;

			if (context_address)
			{
				constexpr std::size_t context_size = 0x4D0;
				static_cast<void>(emulator->read_virtual_memory(
					context_address, buf + 840, context_size));

				std::uint64_t context_rip = 0;
				static_cast<void>(emulator->read_virtual_memory(
					context_address + 0xF8, &context_rip, sizeof(context_rip)));

				*reinterpret_cast<std::uint64_t*>(buf + 3856) = context_rip;
			}

			*reinterpret_cast<std::uint32_t*>(buf + 3840) = 0x80000003;
			*reinterpret_cast<std::uint32_t*>(buf + 3844) = 1;
			*reinterpret_cast<std::uint64_t*>(buf + 4000) = dump_buffer_size;
			*reinterpret_cast<std::uint32_t*>(buf + 3992) = 4;
			*reinterpret_cast<std::uint32_t*>(buf + 4152) = 0x82;
			*reinterpret_cast<std::uint32_t*>(buf + 4176) = 24;

			constexpr emulator_t::address_type shared_data = 0xFFFFF78000000000ull;

			static_cast<void>(emulator->read_virtual_memory(shared_data + 0x14, buf + 4008, 4));
			static_cast<void>(emulator->read_virtual_memory(shared_data + 0x18, buf + 4012, 4));
			static_cast<void>(emulator->read_virtual_memory(shared_data + 0x08, buf + 4144, 4));
			static_cast<void>(emulator->read_virtual_memory(shared_data + 0x0C, buf + 4148, 4));

			*reinterpret_cast<std::uint32_t*>(buf + 8196) = dump_buffer_size;
			*reinterpret_cast<std::uint32_t*>(buf + 8200) = dump_buffer_size - 4;
			*reinterpret_cast<std::uint32_t*>(buf + 8204) = 840;
			*reinterpret_cast<std::uint32_t*>(buf + 8208) = 3840;

			*reinterpret_cast<std::uint32_t*>(buf + dump_buffer_size - 4) = dump_end_signature;

			emulator_err_t error = emulator->write_virtual_memory(output_address, buf, dump_buffer_size);
			error.throw_if("KeCapturePersistentThreadState: write output buffer");

			THREAD_LOG("KeCapturePersistentThreadState: monitoring 0x{:X}-0x{:X} for dump writes",
				output_address, output_address + dump_buffer_size);

			THREAD_LOG("KeCapturePersistentThreadState: wrote 0x{:X} bytes to 0x{:X}", dump_buffer_size, output_address);

			write_return_value(emulator, dump_buffer_size);
		},
		mapped_image,
		"KeCapturePersistentThreadState"
	);
}
