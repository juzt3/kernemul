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

		THREAD_LOG("{} called (type={}, size=0x{:X}, tag=0x{:X}) -> 0x{:X}", caller_name, pool_type, size, tag, *allocation);

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

			THREAD_LOG("ExFreePoolWithTag called (buffer=0x{:X}, tag={})", rcx, rdx);
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

			THREAD_LOG("RtlCompareMemory called (source1=0x{:X}, source2=0x{:X}, length=0x{:X})", rcx, rdx, r8);

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

			THREAD_LOG("RtlCompareMemory returned 0x{:X}", matching_bytes);

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

			THREAD_LOG("MmIsAddressValid called (address=0x{:X}, valid={})", virtual_address, result);

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
				THREAD_WARN_LOG("MmGetSystemRoutineAddress called with null argument");
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

			THREAD_LOG("MmGetSystemRoutineAddress called (name='{}')", routine_name);

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
				THREAD_LOG("MmGetSystemRoutineAddress: found '{}' at 0x{:X}", routine_name, result);
			}
			else
			{
				THREAD_WARN_LOG("MmGetSystemRoutineAddress: '{}' not found", routine_name);
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

			THREAD_LOG("MmGetPhysicalMemoryRanges called ({} ranges, buffer=0x{:X})",
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

			THREAD_LOG("MmAllocateContiguousMemorySpecifyCache called (size=0x{:X}, lowest=0x{:X}, highest=0x{:X}, boundary=0x{:X}, cache_type={}) -> 0x{:X}",
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

			if (virtual_address == 0xF0F87C3E1000)
			{
				const auto current_cr3 = emulator->read_register<x86::reg::cr3, cr3>();

				write_return_value(emulator, current_cr3.address_of_page_directory << 12);

				return;
			}

			const auto physical_address = emulator->translate_virtual_address(virtual_address);

			if (!physical_address)
			{
				THREAD_WARN_LOG("MmGetPhysicalAddress called with invalid virtual address 0x{:X}", virtual_address);

				write_return_value(emulator, 0);

				return;
			}

			THREAD_LOG("MmGetPhysicalAddress called (virtual=0x{:X}) -> 0x{:X}", virtual_address, *physical_address);

			write_return_value(emulator, *physical_address);
		},
		mapped_image,
		"MmGetPhysicalAddress"
	);

	redirect_function(
		[emulator]
		{
			const auto virtual_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto length = emulator->read_register<x86::reg::rdx, std::uint32_t>();
	
			const auto page_count = static_cast<std::uint64_t>(
				((virtual_address & 0xFFF) + length + 0xFFF) >> 12);
			const auto mdl_size = static_cast<std::uint32_t>(8 * page_count + sizeof(_MDL));

			const auto allocation = emulator->heap_allocate(mdl_size, prot_read_write, true);

			emulator_err_t error = allocation.error_or({});
			error.throw_if("IoAllocateMdl: allocate MDL");

			const auto mdl_address = *allocation;

			_MDL mdl = { };

			mdl.Next = nullptr;
			mdl.Size = static_cast<SHORT>(8 * (page_count + 6));
			mdl.MdlFlags = (page_count <= 0x11) ? 8 : 0;
			mdl.StartVa = reinterpret_cast<PVOID>(virtual_address & 0xFFFFFFFFFFFFF000ull);
			mdl.ByteCount = length;
			mdl.ByteOffset = static_cast<ULONG>(virtual_address & 0xFFF);

			error = emulator->write_virtual_memory(mdl_address, &mdl, sizeof(mdl));
			error.throw_if("IoAllocateMdl: write MDL");

			THREAD_LOG("IoAllocateMdl called (va=0x{:X}, length=0x{:X}, pages={}) -> 0x{:X}",
				virtual_address, length, page_count, mdl_address);

			write_return_value(emulator, mdl_address);
		},
		mapped_image,
		"IoAllocateMdl"
	);

	redirect_function(
		[emulator]
		{
			const emulator_t::address_type mdl_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			_MDL mdl = { };
			emulator_err_t error = emulator->read_virtual_memory(mdl_address, &mdl, sizeof(mdl));
			error.throw_if("MmBuildMdlForNonPagedPool: read MDL");

			const emulator_t::address_type start_va = reinterpret_cast<emulator_t::address_type>(mdl.StartVa);
			const ULONG byte_offset = mdl.ByteOffset;
			const ULONG byte_count = mdl.ByteCount;

			mdl.Process = nullptr;
			mdl.MappedSystemVa = reinterpret_cast<PVOID>(start_va + byte_offset);

			const std::uint64_t page_count = ((byte_offset + static_cast<std::uint64_t>(byte_count) + 0xFFF) >> 12);
			const emulator_t::address_type pfn_array_address = mdl_address + sizeof(_MDL);

			for (std::uint64_t i = 0; i < page_count; ++i)
			{
				const emulator_t::address_type page_va = start_va + i * 0x1000;
				const std::optional<emulator_t::address_type> physical = emulator->translate_virtual_address(page_va);

				const std::uint64_t pfn = physical ? (*physical >> 12) : 0ull;

				error = emulator->write_virtual_memory(
					pfn_array_address + i * sizeof(std::uint64_t), &pfn, sizeof(pfn));
				error.throw_if("MmBuildMdlForNonPagedPool: write PFN");
			}

			constexpr std::uint16_t mdl_source_is_nonpaged_pool = 0x4;
			mdl.MdlFlags |= mdl_source_is_nonpaged_pool;

			error = emulator->write_virtual_memory(mdl_address, &mdl, sizeof(mdl));
			error.throw_if("MmBuildMdlForNonPagedPool: write MDL");

			THREAD_LOG("MmBuildMdlForNonPagedPool called (mdl=0x{:X}, va=0x{:X}, pages={})",
				mdl_address, start_va + byte_offset, page_count);
		},
		mapped_image,
		"MmBuildMdlForNonPagedPool"
	);
}
