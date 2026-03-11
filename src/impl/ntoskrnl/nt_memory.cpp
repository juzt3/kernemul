#include "nt_helpers.hpp"

void redirect_ntoskrnl_memory_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image, const portable_executable::image_t* const pe_image)
{
	redirect_image_export(
		[emulator]
		{
			const auto ecx = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();
			const auto r8d = emulator->read_register<x86::reg::r8, std::uint32_t>();

			spdlog::info("ExAllocatePoolWithTag called (type={}, size=0x{:X}, tag={})", ecx, rdx, r8d);

			const auto allocation = emulator->heap_allocate(rdx, prot_read_write, true);

			const emulator_err_t error = allocation.error_or({});

			error.throw_if("pool heap allocation");

			emulator->write_register<x86::reg::rax>(*allocation);
		},
		pe_image,
		mapped_image,
		"ExAllocatePoolWithTag"
	);

	redirect_image_export(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();

			spdlog::info("ExFreePoolWithTag called (buffer=0x{:X}, tag={})", rcx, rdx);
		},
		pe_image,
		mapped_image,
		"ExFreePoolWithTag"
	);

	redirect_image_export(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rdx = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto r8 = emulator->read_register<x86::reg::r8, std::uint64_t>();

			spdlog::info("RtlCompareMemory called (source1=0x{:X}, source2=0x{:X}, length=0x{:X})", rcx, rdx, r8);

			std::uint64_t matching_bytes = 0;

			if (r8 > 0)
			{
				std::vector<std::uint8_t> buffer1(r8);
				std::vector<std::uint8_t> buffer2(r8);

				emulator_err_t error = emulator->read_virtual_memory(rcx, buffer1.data(), r8);

				error.throw_if("read memory");

				error = emulator->read_virtual_memory(rdx, buffer2.data(), r8);

				error.throw_if("read memory");

				for (std::uint64_t i = 0; i < r8; ++i)
				{
					if (buffer1[i] != buffer2[i])
					{
						break;
					}

					++matching_bytes;
				}
			}

			spdlog::info("RtlCompareMemory returned 0x{:X}", matching_bytes);

			write_return_value(emulator, matching_bytes);
		},
		pe_image,
		mapped_image,
		"RtlCompareMemory"
	);
}
