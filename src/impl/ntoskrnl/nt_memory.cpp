#include "nt_helpers.hpp"

void redirect_ntoskrnl_memory_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	const auto pool_allocate_handler = [emulator](const std::string_view caller_name)
	{
		const auto pool_type = emulator->read_register<x86::reg::rcx, std::uint32_t>();
		const auto size = emulator->read_register<x86::reg::rdx, std::uint64_t>();
		const auto tag = emulator->read_register<x86::reg::r8, std::uint32_t>();

		const auto allocation = emulator->heap_allocate(size, prot_read_write, true);

		const emulator_err_t error = allocation.error_or({});

		error.throw_if("pool heap allocation");

		spdlog::info("{} called (type={}, size=0x{:X}, tag=0x{:X}) -> 0x{:X}", caller_name, pool_type, size, tag, *allocation);

		emulator->write_register<x86::reg::rax>(*allocation);
	};

	redirect_function(
		[pool_allocate_handler] { pool_allocate_handler("ExAllocatePoolWithTag"); },
		mapped_image,
		"ExAllocatePoolWithTag"
	);

	redirect_function(
		[pool_allocate_handler, emulator]
		{
			constexpr std::uint64_t default_tag = 0x656E6F4E;
			emulator->write_register<x86::reg::r8>(default_tag);

			pool_allocate_handler("ExAllocatePool");
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

	redirect_function(
		[emulator]
		{
			const auto virtual_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto result = emulator->translate_virtual_address(virtual_address).has_value();

			spdlog::info("MmIsAddressValid called (address=0x{:X}, valid={})", virtual_address, result);

			write_return_value(emulator, result);
		},
		mapped_image,
		"MmIsAddressValid"
	);

	redirect_function(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			if (!rcx)
			{
				spdlog::warn("MmGetSystemRoutineAddress called with null argument");
				write_return_value(emulator, 0);
				return;
			}

			const auto unicode_string = emulator_object_t<UNICODE_STRING>::view_at(emulator, rcx).read();
			const auto buffer_address = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

			std::string routine_name;

			if (buffer_address && unicode_string.Length)
			{
				routine_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
			}

			spdlog::info("MmGetSystemRoutineAddress called (name='{}')", routine_name);

			if (routine_name.empty())
			{
				write_return_value(emulator, 0);
				return;
			}

			emulator_t::address_type result = 0;

			if (const auto ntoskrnl = kernel::find_module("ntoskrnl.exe"))
			{
				if (const auto address = ntoskrnl->find_symbol(routine_name))
				{
					result = *address;
				}
			}

			if (!result)
			{
				if (const auto hal = kernel::find_module("HAL.dll"))
				{
					if (const auto address = hal->find_symbol(routine_name))
					{
						result = *address;
					}
				}
			}

			if (result)
			{
				spdlog::info("MmGetSystemRoutineAddress: found '{}' at 0x{:X}", routine_name, result);
			}
			else
			{
				spdlog::warn("MmGetSystemRoutineAddress: '{}' not found", routine_name);
			}

			write_return_value(emulator, result);
		},
		mapped_image,
		"MmGetSystemRoutineAddress"
	);

	redirect_function(
		[emulator]
		{
			const auto ranges = emulator->physical_memory_ranges();

			std::vector<_PHYSICAL_MEMORY_RANGE> guest_ranges;
			guest_ranges.reserve(ranges.size() + 1);

			for (const auto& range : ranges)
			{
				_PHYSICAL_MEMORY_RANGE entry = { };
				entry.BaseAddress = range.physical_address;
				entry.NumberOfBytes.QuadPart = static_cast<LONGLONG>(range.size);
				guest_ranges.push_back(entry);
			}

			constexpr _PHYSICAL_MEMORY_RANGE terminator = { };
			guest_ranges.push_back(terminator);

			const auto buffer_size = guest_ranges.size() * sizeof(_PHYSICAL_MEMORY_RANGE);
			const auto allocation = emulator->heap_allocate(buffer_size, prot_read_write, true);

			emulator_err_t error = allocation.error_or({});
			error.throw_if("allocate MmGetPhysicalMemoryRanges buffer");

			error = emulator->write_virtual_memory(*allocation, guest_ranges.data(), buffer_size);
			error.throw_if("write MmGetPhysicalMemoryRanges buffer");

			spdlog::info("MmGetPhysicalMemoryRanges called ({} ranges, buffer=0x{:X})",
				ranges.size(), *allocation);

			write_return_value(emulator, *allocation);
		},
		mapped_image,
		"MmGetPhysicalMemoryRanges"
	);

	redirect_function(
		[emulator]
		{
			const auto size = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto lowest = emulator->read_register<x86::reg::rdx, std::uint64_t>();
			const auto highest = emulator->read_register<x86::reg::r8, std::uint64_t>();
			const auto boundary = emulator->read_register<x86::reg::r9, std::uint64_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
			std::uint32_t cache_type = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &cache_type, sizeof(cache_type)));

			const auto allocation = emulator->heap_allocate(size, prot_read_write, true);

			const emulator_err_t error = allocation.error_or({});
			error.throw_if("contiguous memory allocation");

			spdlog::info("MmAllocateContiguousMemorySpecifyCache called (size=0x{:X}, lowest=0x{:X}, highest=0x{:X}, boundary=0x{:X}, cache_type={}) -> 0x{:X}",
				size, lowest, highest, boundary, cache_type, *allocation);

			write_return_value(emulator, *allocation);
		},
		mapped_image,
		"MmAllocateContiguousMemorySpecifyCache"
	);

	redirect_function(
		[emulator]
		{
			const auto virtual_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			const auto physical_address = emulator->translate_virtual_address(virtual_address);

			if (!physical_address)
			{
				spdlog::warn("MmGetPhysicalAddress called with invalid virtual address 0x{:X}", virtual_address);

				write_return_value(emulator, 0);

				return;
			}

			spdlog::info("MmGetPhysicalAddress called (virtual=0x{:X}) -> 0x{:X}", virtual_address, *physical_address);

			write_return_value(emulator, *physical_address);
		},
		mapped_image,
		"MmGetPhysicalAddress"
	);
}
