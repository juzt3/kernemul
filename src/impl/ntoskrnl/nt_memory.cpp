#include "nt_helpers.hpp"

void redirect_ntoskrnl_memory_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image)
{
	const auto pool_allocate_handler = [emulator](const std::string_view caller_name)
	{
		const auto pool_type = emulator->read_register<x86::reg::rcx, std::uint32_t>();
		const auto size = emulator->read_register<x86::reg::rdx, std::uint64_t>();
		const auto tag = emulator->read_register<x86::reg::r8, std::uint32_t>();

		spdlog::info("{} called (type={}, size=0x{:X}, tag=0x{:X})", caller_name, pool_type, size, tag);

		const auto allocation = emulator->heap_allocate(size, prot_read_write, true);

		const emulator_err_t error = allocation.error_or({});

		error.throw_if("pool heap allocation");

		emulator->write_register<x86::reg::rax>(*allocation);
	};

	redirect_function(
		[pool_allocate_handler] { pool_allocate_handler("ExAllocatePoolWithTag"); },
		mapped_image,
		"ExAllocatePoolWithTag"
	);

	redirect_function(
		[emulator]
		{
			const auto pool_type = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto size = emulator->read_register<x86::reg::rdx, std::uint64_t>();

			spdlog::info("ExAllocatePool called (type={}, size=0x{:X})", pool_type, size);

			constexpr std::uint32_t default_tag = 0x656E6F4E;
			emulator->write_register<x86::reg::r8>(static_cast<std::uint64_t>(default_tag));

			const auto allocation = emulator->heap_allocate(size, prot_read_write, true);

			const emulator_err_t error = allocation.error_or({});

			error.throw_if("pool heap allocation");

			emulator->write_register<x86::reg::rax>(*allocation);
		},
		mapped_image,
		"ExAllocatePool"
	);

	redirect_function(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();

			spdlog::info("ExFreePoolWithTag called (buffer=0x{:X}, tag={})", rcx, rdx);
		},
		mapped_image,
		"ExFreePoolWithTag"
	);

	redirect_function(
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
		mapped_image,
		"RtlCompareMemory"
	);
}
