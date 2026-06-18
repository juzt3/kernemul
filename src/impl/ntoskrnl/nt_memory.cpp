#include "nt_helpers.hpp"
#include "../../user/user.hpp"
#include "../../user/user_memory.hpp"

#include <portable_executable/image.hpp>

constexpr std::uint32_t sec_image = 0x1000000;

static std::shared_ptr<file_t> map_pe_image(const std::shared_ptr<file_t>& raw_file)
{
	const auto data = raw_file->read();

	if (data.size() < sizeof(portable_executable::dos_header_t))
	{
		return {};
	}

	const auto pe_image = reinterpret_cast<const portable_executable::image_t*>(data.data());
	const auto dos = pe_image->dos_header();

	if (!dos->valid())
	{
		return {};
	}

	const auto nt = pe_image->nt_headers();
	const auto image_size = nt->optional_header.size_of_image;
	const auto header_size = nt->optional_header.size_of_headers;

	std::vector<std::uint8_t> image_buffer(image_size, 0);

	const auto headers_to_copy = std::min(static_cast<std::size_t>(header_size), data.size());
	std::memcpy(image_buffer.data(), data.data(), headers_to_copy);

	for (const auto& section : pe_image->sections())
	{
		if (section.virtual_address == 0 || section.size_of_raw_data == 0)
		{
			continue;
		}

		const auto raw_offset = section.pointer_to_raw_data;
		const auto raw_size = section.size_of_raw_data;
		const auto virtual_offset = section.virtual_address;

		if (raw_offset + raw_size > data.size())
		{
			continue;
		}

		if (virtual_offset + raw_size > image_size)
		{
			continue;
		}

		std::memcpy(image_buffer.data() + virtual_offset, data.data() + raw_offset, raw_size);
	}

	return std::make_shared<file_t>(std::move(image_buffer));
}

static void handle_allocate_pool_with_tag(const std::shared_ptr<emulator_t>& emulator,
	std::uint32_t pool_type, std::uint64_t size, std::uint32_t tag)
{
	const auto allocation = emulator->heap_allocate(size, prot_read_write, true);

	const emulator_err_t error = allocation.error_or({});

	error.throw_if("pool heap allocation");

	THREAD_LOG("ExAllocatePoolWithTag called (type={}, size=0x{:X}, tag=0x{:X}) -> 0x{:X}", pool_type, size, tag, *allocation);

	emulator->write_register<x86::reg::rax>(*allocation);
}

static void handle_allocate_pool2(const std::shared_ptr<emulator_t>& emulator,
	std::uint32_t pool_type, std::uint64_t size, std::uint32_t tag)
{
	const auto allocation = emulator->heap_allocate(size, prot_read_write, true);

	const emulator_err_t error = allocation.error_or({});

	error.throw_if("pool heap allocation");

	THREAD_LOG("ExAllocatePool2 called (type={}, size=0x{:X}, tag=0x{:X}) -> 0x{:X}", pool_type, size, tag, *allocation);

	emulator->write_register<x86::reg::rax>(*allocation);
}

static void handle_allocate_pool(const std::shared_ptr<emulator_t>& emulator,
	std::uint32_t pool_type, std::uint64_t size)
{
	constexpr std::uint32_t default_tag = 0x656E6F4E;

	const auto allocation = emulator->heap_allocate(size, prot_read_write, true);

	const emulator_err_t error = allocation.error_or({});

	error.throw_if("pool heap allocation");

	THREAD_LOG("ExAllocatePool called (type={}, size=0x{:X}, tag=0x{:X}) -> 0x{:X}", pool_type, size, default_tag, *allocation);

	emulator->write_register<x86::reg::rax>(*allocation);
}

static void handle_free_pool_with_tag(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t buffer, std::uint64_t tag)
{
	THREAD_LOG("ExFreePoolWithTag called (buffer=0x{:X}, tag={})", buffer, tag);
}

static void handle_compare_memory(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type source1, emulator_t::address_type source2, std::uint64_t length)
{
	THREAD_LOG("RtlCompareMemory called (source1=0x{:X}, source2=0x{:X}, length=0x{:X})", source1, source2, length);

	std::uint64_t matching_bytes = 0;

	if (length > 0)
	{
		std::vector<std::uint8_t> buffer1(length);
		std::vector<std::uint8_t> buffer2(length);

		emulator_err_t error = emulator->read_virtual_memory(source1, buffer1.data(), length);

		error.throw_if("read memory");

		error = emulator->read_virtual_memory(source2, buffer2.data(), length);

		error.throw_if("read memory");

		for (std::uint64_t i = 0; i < length; ++i)
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
}

static void handle_is_address_valid(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type virtual_address)
{
	const auto result = emulator->translate_virtual_address(virtual_address).has_value();

	THREAD_LOG("MmIsAddressValid called (address=0x{:X}, valid={})", virtual_address, result);

	write_return_value(emulator, result);
}

static void handle_get_system_routine_address(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type unicode_string_address)
{
	if (!unicode_string_address)
	{
		THREAD_WARN_LOG("MmGetSystemRoutineAddress called with null argument");
		write_return_value(emulator, 0);
		return;
	}

	const auto unicode_string = emulator_object_t<UNICODE_STRING>::view_at(emulator, unicode_string_address).read();
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
}

static void handle_get_physical_memory_ranges(const std::shared_ptr<emulator_t>& emulator)
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
}

static void handle_allocate_contiguous_memory_specify_cache(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t size, std::uint64_t lowest, std::uint64_t highest, std::uint64_t boundary,
	std::uint32_t cache_type)
{
	const auto allocation = emulator->heap_allocate(size, prot_read_write, true);

	const emulator_err_t error = allocation.error_or({});
	error.throw_if("contiguous memory allocation");

	THREAD_LOG("MmAllocateContiguousMemorySpecifyCache called (size=0x{:X}, lowest=0x{:X}, highest=0x{:X}, boundary=0x{:X}, cache_type={}) -> 0x{:X}",
		size, lowest, highest, boundary, cache_type, *allocation);

	write_return_value(emulator, *allocation);
}

static void handle_allocate_contiguous_node_memory(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t size, std::uint64_t lowest, std::uint64_t highest, std::uint64_t boundary,
	std::uint32_t cache_type, std::uint32_t preferred_node)
{
	const auto allocation = emulator->heap_allocate(size, prot_read_write, true);

	const emulator_err_t error = allocation.error_or({});
	error.throw_if("contiguous node memory allocation");

	THREAD_LOG("MmAllocateContiguousNodeMemory called (size=0x{:X}, lowest=0x{:X}, highest=0x{:X}, boundary=0x{:X}, cache_type={}, node={}) -> 0x{:X}",
		size, lowest, highest, boundary, cache_type, preferred_node, *allocation);

	write_return_value(emulator, *allocation);
}

static void handle_free_contiguous_memory(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type base_address)
{
	THREAD_LOG("MmFreeContiguousMemory called (base_address=0x{:X})", base_address);

	// todo: actually free the contiguous allocation from the heap
}

static void handle_map_io_space_ex(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t physical_address, std::uint64_t number_of_bytes, std::uint32_t protect_or_cache)
{
	if (number_of_bytes == 0)
	{
		THREAD_WARN_LOG("MmMapIoSpaceEx called with zero size (phys=0x{:X})", physical_address);
		write_return_value(emulator, static_cast<std::uint64_t>(0));
		return;
	}

	constexpr std::uint64_t page_size = 0x1000;
	const auto aligned_phys = physical_address & ~(page_size - 1);
	const auto page_offset = physical_address - aligned_phys;
	const auto aligned_size = (number_of_bytes + page_offset + page_size - 1) & ~(page_size - 1);
	const auto page_count = aligned_size / page_size;

	// ensure the physical pages are backed in the emulator
	for (std::uint64_t i = 0; i < page_count; ++i)
	{
		const auto phys_page = aligned_phys + i * page_size;

		if (!emulator->is_physical_address_valid(phys_page))
		{
			static_cast<void>(emulator->map_physical_memory(phys_page, page_size, prot_read_write));
		}
	}

	// allocate a virtual address range and map each page to the physical address
	const auto virtual_base = emulator->heap_allocate(aligned_size, prot_read_write, true);
	const emulator_err_t alloc_error = virtual_base.error_or({});
	alloc_error.throw_if("MmMapIoSpaceEx: allocate virtual range");

	// remap each virtual page to the requested physical page
	for (std::uint64_t i = 0; i < page_count; ++i)
	{
		const auto virt_page = *virtual_base + i * page_size;
		const auto phys_page = aligned_phys + i * page_size;

		const emulator_err_t error = emulator->map_virtual_page(virt_page, phys_page);
		error.throw_if("MmMapIoSpaceEx: map virtual page");
	}

	const auto result_address = *virtual_base + page_offset;

	THREAD_LOG("MmMapIoSpaceEx called (phys=0x{:X}, size=0x{:X}, cache_type={}) -> 0x{:X}",
		physical_address, number_of_bytes, protect_or_cache, result_address);

	write_return_value(emulator, result_address);
}

static void handle_unmap_io_space(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type base_address, std::uint64_t number_of_bytes)
{
	THREAD_LOG("MmUnmapIoSpace called (base=0x{:X}, size=0x{:X})", base_address, number_of_bytes);

	// todo: actually free the mapped IO space
}

static void handle_get_physical_address(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type virtual_address)
{
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
}

static void handle_get_virtual_for_physical(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t physical_address)
{
	const auto virtual_address = emulator->translate_physical_address(physical_address);

	if (!virtual_address)
	{
		THREAD_WARN_LOG("MmGetVirtualForPhysical called with unmapped physical address 0x{:X}", physical_address);

		write_return_value(emulator, 0);

		return;
	}

	THREAD_LOG("MmGetVirtualForPhysical called (physical=0x{:X}) -> 0x{:X}", physical_address, *virtual_address);

	write_return_value(emulator, *virtual_address);
}

static void handle_copy_memory(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t target_address, std::uint64_t source_address, std::uint64_t number_of_bytes,
	std::uint32_t flags, std::uint64_t bytes_transferred_address)
{
	constexpr std::uint32_t mm_copy_memory_physical = 0x1;
	constexpr std::uint32_t mm_copy_memory_virtual = 0x2;

	if (!number_of_bytes || (flags != mm_copy_memory_physical && flags != mm_copy_memory_virtual))
	{
		THREAD_WARN_LOG("MmCopyMemory called with invalid params (target=0x{:X}, source=0x{:X}, size=0x{:X}, flags=0x{:X})",
			target_address, source_address, number_of_bytes, flags);

		write_nt_status(emulator, 0xC000000D);

		return;
	}

	std::uint64_t resolved_source = source_address;

	if (flags == mm_copy_memory_physical)
	{
		const auto virtual_address = emulator->translate_physical_address(source_address);

		if (!virtual_address)
		{
			THREAD_WARN_LOG("MmCopyMemory called with unmapped physical source 0x{:X}", source_address);

			write_nt_status(emulator, 0x8000000D);

			return;
		}

		resolved_source = *virtual_address;
	}

	std::vector<std::uint8_t> buffer(number_of_bytes);

	const auto read_error = emulator->read_virtual_memory(resolved_source, buffer.data(), number_of_bytes);

	if (read_error)
	{
		THREAD_WARN_LOG("MmCopyMemory failed to read source memory (source=0x{:X}, size=0x{:X})", resolved_source, number_of_bytes);

		write_nt_status(emulator, 0x8000000D);

		return;
	}

	const auto write_error = emulator->write_virtual_memory(target_address, buffer.data(), number_of_bytes);

	if (write_error)
	{
		THREAD_WARN_LOG("MmCopyMemory failed to write target memory (target=0x{:X}, size=0x{:X})", target_address, number_of_bytes);

		write_nt_status(emulator, 0x8000000D);

		return;
	}

	if (bytes_transferred_address)
	{
		static_cast<void>(emulator->write_virtual_memory(bytes_transferred_address, &number_of_bytes, sizeof(number_of_bytes)));
	}

	THREAD_LOG("MmCopyMemory called (target=0x{:X}, source=0x{:X}, size=0x{:X}, flags=0x{:X}) -> success", target_address, source_address, number_of_bytes, flags);

	write_nt_success(emulator);
}

static void handle_map_io_space(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t physical_address, std::uint64_t number_of_bytes, std::uint32_t cache_type_raw)
{
	const auto cache_type = cache_type_raw & 0xFF;

	if (!number_of_bytes || cache_type >= 6)
	{
		THREAD_WARN_LOG("MmMapIoSpace called with invalid params (phys=0x{:X}, size=0x{:X}, cache_type={})",
			physical_address, number_of_bytes, cache_type);
		write_return_value(emulator, 0);
		return;
	}

	constexpr std::uint64_t page_size = 0x1000;
	const auto aligned_physical = physical_address & ~(page_size - 1);
	const auto end_address = physical_address + number_of_bytes;
	const auto aligned_size = ((end_address + page_size - 1) & ~(page_size - 1)) - aligned_physical;

	for (std::uint64_t offset = 0; offset < aligned_size; offset += page_size)
	{
		if (!emulator->is_physical_address_valid(aligned_physical + offset))
		{
			THREAD_WARN_LOG("MmMapIoSpace called - physical address 0x{:X} not valid (phys=0x{:X}, size=0x{:X})",
				aligned_physical + offset, physical_address, number_of_bytes);
			write_return_value(emulator, 0);
			return;
		}
	}

	const auto allocation = emulator->heap_allocate(aligned_size, prot_read_write, true);
	emulator_err_t error = allocation.error_or({});
	error.throw_if("MmMapIoSpace: allocate virtual range");

	const auto virtual_base = *allocation;

	for (std::uint64_t offset = 0; offset < aligned_size; offset += page_size)
	{
		error = emulator->map_virtual_page(virtual_base + offset, aligned_physical + offset);
		error.throw_if("MmMapIoSpace: map virtual page");
	}

	const auto result = virtual_base + (physical_address - aligned_physical);

	THREAD_LOG("MmMapIoSpace called (phys=0x{:X}, size=0x{:X}, cache_type={}) -> 0x{:X}",
		physical_address, number_of_bytes, cache_type, result);

	write_return_value(emulator, result);
}

static void handle_unmap_io_space_2(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type base_address, std::uint64_t number_of_bytes)
{
	THREAD_LOG("MmUnmapIoSpace called (base address=0x{:X}, size=0x{:X})", base_address, number_of_bytes);
}

static void handle_allocate_mdl(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type virtual_address, std::uint32_t length)
{
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
}

static void handle_free_mdl(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type mdl_address)
{
	THREAD_LOG("IoFreeMdl called (mdl=0x{:X})", mdl_address);
}

static void handle_mm_create_section(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type section_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes, emulator_t::address_type max_size_ptr,
	std::uint32_t section_page_protection, std::uint32_t allocation_attributes,
	emulator_t::address_type file_handle, emulator_t::address_type file_object_address)
{
	std::int64_t max_size = 0;
	if (max_size_ptr)
	{
		emulator_err_t error = emulator->read_virtual_memory(max_size_ptr, &max_size, sizeof(max_size));
		error.throw_if("MmCreateSection: read MaximumSize value");
	}

	std::shared_ptr<file_object_t> file_obj;
	std::string file_path;

	if (file_object_address)
	{
		file_obj = kernel::object_manager->get_object<file_object_t>(file_object_address);
	}

	if (!file_obj && file_handle)
	{
		file_obj = kernel::active_handle_table().get_object_from_handle<file_object_t>(file_handle);
	}

	if (file_obj)
	{
		file_path = file_obj->path;
	}

	THREAD_LOG("MmCreateSection called (section_out=0x{:X}, access=0x{:X}, oa=0x{:X}, max_size={}, protection=0x{:X}, alloc_attrs=0x{:X}, file_handle=0x{:X}, file_object=0x{:X}, path='{}')",
		section_out, desired_access, object_attributes, max_size, section_page_protection, allocation_attributes, file_handle, file_object_address, file_path);

	std::shared_ptr<file_t> backing_file;

	if (file_obj && file_obj->file)
	{
		backing_file = file_obj->file;
	}

	std::uint64_t mm_preferred_base = 0;
	const bool mm_is_image = (allocation_attributes & sec_image) != 0;

	if (backing_file && mm_is_image)
	{
		const auto raw_data = backing_file->read();
		if (raw_data.size() >= sizeof(portable_executable::dos_header_t))
		{
			const auto* pe = reinterpret_cast<const portable_executable::image_t*>(raw_data.data());
			if (pe->dos_header()->valid())
			{
				mm_preferred_base = pe->nt_headers()->optional_header.image_base;
			}
		}

		auto mapped = map_pe_image(backing_file);

		if (mapped)
		{
			THREAD_LOG("MmCreateSection: SEC_IMAGE detected, PE-mapped {} -> {} bytes (preferred_base=0x{:X})", backing_file->size(), mapped->size(), mm_preferred_base);
			backing_file = mapped;
		}
		else
		{
			THREAD_WARN_LOG("MmCreateSection: SEC_IMAGE set but PE mapping failed for '{}'", file_path);
		}
	}

	auto host_object = std::make_shared<section_object_t>(backing_file);
	host_object->is_image = mm_is_image;
	host_object->preferred_base = mm_preferred_base;

	constexpr std::size_t section_body_size = 0x40;
	std::array<std::uint8_t, section_body_size> body{};

	if (backing_file)
	{
		const std::int64_t file_size = static_cast<std::int64_t>(backing_file->size());
		std::memcpy(body.data() + 0x30, &file_size, sizeof(file_size));
	}
	else if (max_size > 0)
	{
		std::memcpy(body.data() + 0x30, &max_size, sizeof(max_size));
	}

	const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size(), host_object);

	if (section_out)
	{
		emulator_err_t error = emulator->write_virtual_memory(section_out, &body_address, sizeof(body_address));
		error.throw_if("MmCreateSection: write output");
	}

	THREAD_LOG("MmCreateSection: created section at 0x{:X} (path='{}', size={})",
		body_address, file_path, backing_file ? backing_file->size() : 0);

	write_nt_success(emulator);
}

static void handle_create_section(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type section_handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes, emulator_t::address_type max_size_ptr,
	std::uint32_t section_page_protection, std::uint32_t allocation_attributes,
	emulator_t::address_type file_handle)
{
	std::int64_t max_size = 0;
	if (max_size_ptr)
	{
		emulator_err_t error = emulator->read_virtual_memory(max_size_ptr, &max_size, sizeof(max_size));
		error.throw_if("NtCreateSection: read MaximumSize value");
	}

	std::shared_ptr<file_object_t> file_obj;
	std::string file_path;

	if (file_handle)
	{
		file_obj = kernel::active_handle_table().get_object_from_handle<file_object_t>(file_handle);
	}

	if (file_obj)
	{
		file_path = file_obj->path;
	}

	THREAD_LOG("NtCreateSection called (section_handle_out=0x{:X}, access=0x{:X}, oa=0x{:X}, max_size={}, protection=0x{:X}, alloc_attrs=0x{:X}, file_handle=0x{:X}, path='{}')",
		section_handle_out, desired_access, object_attributes, max_size, section_page_protection, allocation_attributes, file_handle, file_path);

	std::shared_ptr<file_t> backing_file;

	if (file_obj && file_obj->file)
	{
		backing_file = file_obj->file;
	}

	std::uint64_t preferred_base = 0;
	const bool is_image = (allocation_attributes & sec_image) != 0;

	if (backing_file && is_image)
	{
		const auto raw_data = backing_file->read();
		if (raw_data.size() >= sizeof(portable_executable::dos_header_t))
		{
			const auto* pe = reinterpret_cast<const portable_executable::image_t*>(raw_data.data());
			if (pe->dos_header()->valid())
			{
				preferred_base = pe->nt_headers()->optional_header.image_base;
			}
		}

		auto mapped = map_pe_image(backing_file);

		if (mapped)
		{
			THREAD_LOG("NtCreateSection: SEC_IMAGE detected, PE-mapped {} -> {} bytes (preferred_base=0x{:X})", backing_file->size(), mapped->size(), preferred_base);
			backing_file = mapped;
		}
		else
		{
			THREAD_WARN_LOG("NtCreateSection: SEC_IMAGE set but PE mapping failed for '{}'", file_path);
		}
	}

	auto host_object = std::make_shared<section_object_t>(backing_file);
	host_object->is_image = is_image;
	host_object->preferred_base = preferred_base;

	constexpr std::size_t section_body_size = 0x40;
	std::array<std::uint8_t, section_body_size> body{};

	if (backing_file)
	{
		const std::int64_t file_size = static_cast<std::int64_t>(backing_file->size());
		std::memcpy(body.data() + 0x30, &file_size, sizeof(file_size));
	}
	else if (max_size > 0)
	{
		std::memcpy(body.data() + 0x30, &max_size, sizeof(max_size));
	}

	const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size(), host_object);
	const auto section_handle = kernel::active_handle_table().create_handle(body_address, desired_access);

	if (section_handle_out)
	{
		emulator_err_t error = emulator->write_virtual_memory(section_handle_out, &section_handle, sizeof(section_handle));
		error.throw_if("NtCreateSection: write handle");
	}

	THREAD_LOG("NtCreateSection: created section handle 0x{:X} at 0x{:X} (path='{}', size={})",
		section_handle, body_address, file_path, backing_file ? backing_file->size() : 0);

	write_nt_success(emulator);
}

static void handle_open_section(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type section_handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes_address)
{
	std::string section_name;
	emulator_t::address_type root_directory_handle = 0;

	if (object_attributes_address)
	{
		auto oa_object = emulator_object_t<OBJECT_ATTRIBUTES>::view_at(emulator, object_attributes_address);
		const auto oa = oa_object.read();

		root_directory_handle = reinterpret_cast<emulator_t::address_type>(oa.RootDirectory);

		const auto object_name_address = reinterpret_cast<emulator_t::address_type>(oa.ObjectName);

		if (object_name_address)
		{
			auto us_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, object_name_address);
			const auto us = us_object.read();

			const auto buffer_address = reinterpret_cast<emulator_t::address_type>(us.Buffer);

			if (buffer_address && us.Length > 0)
			{
				const auto char_count = us.Length / sizeof(wchar_t);
				std::wstring wide_name(char_count, L'\0');
				emulator_err_t error = emulator->read_virtual_memory(
					buffer_address, wide_name.data(), us.Length);
				error.throw_if("NtOpenSection: read object name");
				section_name = util::narrow_wstring(wide_name);
			}
		}
	}

	THREAD_LOG("NtOpenSection called (handle_out=0x{:X}, access=0x{:X}, name='{}')",
		section_handle_out, desired_access, section_name);

	if (section_name == "\\Windows\\SharedSection")
	{
		auto host_object = std::make_shared<section_object_t>(nullptr);

		constexpr std::size_t section_body_size = 0x40;
		std::array<std::uint8_t, section_body_size> body{};

		constexpr std::int64_t shared_section_size = 0x10000;
		std::memcpy(body.data() + 0x30, &shared_section_size, sizeof(shared_section_size));

		const auto body_address = kernel::object_manager->create_object(
			0, body.data(), body.size(), host_object);
		const auto handle = kernel::active_handle_table().create_handle(body_address, desired_access);

		if (section_handle_out)
		{
			emulator_err_t error = emulator->write_virtual_memory(
				section_handle_out, &handle, sizeof(handle));
			error.throw_if("NtOpenSection: write handle");
		}

		THREAD_LOG("NtOpenSection: created SharedSection handle 0x{:X}", handle);
		write_nt_success(emulator);
		return;
	}

	// check if this is a KnownDlls lookup (RootDirectory is the \KnownDlls handle)
	if (root_directory_handle && !section_name.empty())
	{
		const auto dir_obj = kernel::active_handle_table().get_object_from_handle<directory_object_t>(root_directory_handle);

		if (dir_obj && (dir_obj->name == "\\KnownDlls" || dir_obj->name == "\\KnownDlls32"))
		{
			auto lower_name = section_name;
			for (auto& c : lower_name)
			{
				c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
			}

			const auto vfs_path = "system32/" + lower_name;
			const auto file = kernel::filesystem->open_at(vfs_path);

			if (file)
			{
				auto mapped = map_pe_image(file);
				if (!mapped)
				{
					mapped = file;
				}

				std::uint64_t preferred_base = 0;
				const auto raw_data = file->read();
				if (raw_data.size() >= sizeof(portable_executable::dos_header_t))
				{
					const auto* pe = reinterpret_cast<const portable_executable::image_t*>(raw_data.data());
					if (pe->dos_header()->valid())
					{
						preferred_base = pe->nt_headers()->optional_header.image_base;
					}
				}

				auto host_object = std::make_shared<section_object_t>(mapped);
				host_object->is_image = true;
				host_object->preferred_base = preferred_base;

				constexpr std::size_t section_body_size = 0x40;
				std::array<std::uint8_t, section_body_size> body{};

				const std::int64_t file_size = static_cast<std::int64_t>(mapped->size());
				std::memcpy(body.data() + 0x30, &file_size, sizeof(file_size));

				const auto body_address = kernel::object_manager->create_object(
					0, body.data(), body.size(), host_object);
				const auto handle = kernel::active_handle_table().create_handle(body_address, desired_access);

				if (section_handle_out)
				{
					emulator_err_t error = emulator->write_virtual_memory(
						section_handle_out, &handle, sizeof(handle));
					error.throw_if("NtOpenSection: write handle");
				}

				THREAD_LOG("NtOpenSection: KnownDll '{}' -> section handle 0x{:X} (size={})",
					section_name, handle, mapped->size());
				write_nt_success(emulator);
				return;
			}
		}
	}

	const auto existing = kernel::object_manager->lookup_named_object(section_name);

	if (existing)
	{
		const auto handle = kernel::active_handle_table().create_handle(*existing, desired_access);

		if (section_handle_out)
		{
			emulator_err_t error = emulator->write_virtual_memory(
				section_handle_out, &handle, sizeof(handle));
			error.throw_if("NtOpenSection: write handle");
		}

		THREAD_LOG("NtOpenSection: opened handle 0x{:X} for section '{}' at 0x{:X}",
			handle, section_name, *existing);
		write_nt_success(emulator);
		return;
	}

	THREAD_LOG("NtOpenSection: section '{}' not found", section_name);
	write_nt_status(emulator, 0xC0000034);
}

static void handle_map_view_in_system_space(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type section_address, emulator_t::address_type mapped_base_out,
	emulator_t::address_type view_size_ptr)
{
	std::uint64_t view_size = 0;
	if (view_size_ptr)
	{
		emulator_err_t error = emulator->read_virtual_memory(view_size_ptr, &view_size, sizeof(view_size));
		error.throw_if("MmMapViewInSystemSpace: read ViewSize");
	}

	THREAD_LOG("MmMapViewInSystemSpace called (section=0x{:X}, mapped_base_out=0x{:X}, view_size_ptr=0x{:X}, view_size=0x{:X})",
		section_address, mapped_base_out, view_size_ptr, view_size);

	const auto section = kernel::object_manager->get_object<section_object_t>(section_address);

	if (!section || !section->file)
	{
		THREAD_WARN_LOG("MmMapViewInSystemSpace: section 0x{:X} has no backing file", section_address);

		write_nt_status(emulator, 0xC000000D);
		return;
	}

	const auto data = section->file->read();
	const std::uint64_t file_size = data.size();

	if (view_size == 0)
	{
		view_size = file_size;
	}

	const auto mapping = emulator->heap_allocate(view_size, prot_read_write, true);
	emulator_err_t error = mapping.error_or({});
	error.throw_if("MmMapViewInSystemSpace: allocate mapping");

	const std::uint64_t copy_size = std::min(view_size, file_size);

	if (copy_size > 0)
	{
		error = emulator->write_virtual_memory(*mapping, data.data(), copy_size);
		error.throw_if("MmMapViewInSystemSpace: write file data");
	}

	if (mapped_base_out)
	{
		error = emulator->write_virtual_memory(mapped_base_out, &*mapping, sizeof(*mapping));
		error.throw_if("MmMapViewInSystemSpace: write MappedBase");
	}

	if (view_size_ptr)
	{
		error = emulator->write_virtual_memory(view_size_ptr, &view_size, sizeof(view_size));
		error.throw_if("MmMapViewInSystemSpace: write ViewSize");
	}

	const auto mapping_base = *mapping;

	THREAD_LOG("MmMapViewInSystemSpace: mapped 0x{:X} bytes at 0x{:X}", view_size, mapping_base);

	write_nt_success(emulator);
}

static void handle_map_view_of_section(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t section_handle, emulator_t::address_type process_handle,
	emulator_t::address_type base_address_ptr, std::uint64_t zero_bits,
	std::uint64_t commit_size, emulator_t::address_type section_offset_ptr,
	emulator_t::address_type view_size_ptr, std::uint32_t inherit_disposition,
	std::uint32_t allocation_type, std::uint32_t win32_protect)
{
	std::int64_t section_offset = 0;
	emulator_err_t error;
	if (section_offset_ptr)
	{
		error = emulator->read_virtual_memory(section_offset_ptr, &section_offset, sizeof(section_offset));
		error.throw_if("NtMapViewOfSection: read SectionOffset value");
	}

	std::uint64_t view_size = 0;
	if (view_size_ptr)
	{
		error = emulator->read_virtual_memory(view_size_ptr, &view_size, sizeof(view_size));
		error.throw_if("NtMapViewOfSection: read ViewSize value");
	}

	THREAD_LOG("NtMapViewOfSection called (section_handle=0x{:X}, process_handle=0x{:X}, base_out=0x{:X}, zero_bits=0x{:X}, commit_size=0x{:X}, section_offset=0x{:X}, view_size=0x{:X}, protect=0x{:X})",
		section_handle, process_handle, base_address_ptr, zero_bits, commit_size, section_offset, view_size, win32_protect);

	const auto section = kernel::active_handle_table().get_object_from_handle<section_object_t>(section_handle);

	if (!section)
	{
		THREAD_WARN_LOG("NtMapViewOfSection: invalid section handle 0x{:X}", section_handle);

		write_nt_status(emulator, 0xC0000008);
		return;
	}

	std::span<const std::uint8_t> data;

	if (section->file)
	{
		data = section->file->read();
	}

	const std::uint64_t file_size = data.size();
	const std::uint64_t offset = (section_offset > 0) ? static_cast<std::uint64_t>(section_offset) : 0;

	if (view_size == 0)
	{
		view_size = (offset < file_size) ? (file_size - offset) : file_size;
	}

	if (view_size == 0)
	{
		view_size = 0x1000;
	}

	emulator_t::address_type mapping_address = 0;

	if (user::memory_manager)
	{
		mapping_address = user::memory_manager->allocate_pages(
			view_size, user::page_readwrite);

		if (!mapping_address)
		{
			THREAD_WARN_LOG("NtMapViewOfSection: usermode allocation failed for 0x{:X} bytes", view_size);
			write_nt_status(emulator, 0xC0000018);
			return;
		}

		user::memory_manager->register_mapped(mapping_address, view_size, user::page_readwrite);
	}
	else
	{
		const auto mapping = emulator->heap_allocate(view_size, prot_read_write, true);
		error = mapping.error_or({});
		error.throw_if("NtMapViewOfSection: allocate mapping");
		mapping_address = *mapping;
	}

	std::uint64_t copy_size = 0;

	if (offset < file_size)
	{
		copy_size = std::min(view_size, file_size - offset);
	}

	if (copy_size > 0)
	{
		if (section->is_image && mapping_address != section->preferred_base && copy_size >= sizeof(portable_executable::dos_header_t))
		{
			std::vector<std::uint8_t> relocated_data(data.data() + offset, data.data() + offset + copy_size);

			auto* pe = reinterpret_cast<portable_executable::image_t*>(relocated_data.data());

			if (pe->dos_header()->valid())
			{
				const auto delta = static_cast<std::int64_t>(mapping_address) -
					static_cast<std::int64_t>(section->preferred_base);

				std::size_t reloc_count = 0;

				for (const auto [descriptor, virtual_address] : pe->relocations())
				{
					if (descriptor.type == portable_executable::relocation_type_t::dir64)
					{
						const auto patch_rva = virtual_address + descriptor.offset;

						if (patch_rva + sizeof(std::uint64_t) <= relocated_data.size())
						{
							auto* patch = reinterpret_cast<std::uint64_t*>(relocated_data.data() + patch_rva);
							*patch += delta;
							++reloc_count;
						}
					}
				}

				pe->nt_headers()->optional_header.image_base = mapping_address;

				THREAD_LOG("NtMapViewOfSection: applied {} base relocations (delta=0x{:X}), patched ImageBase to 0x{:X}",
					reloc_count, static_cast<std::uint64_t>(delta), mapping_address);
			}

			error = emulator->write_virtual_memory(mapping_address, relocated_data.data(), relocated_data.size());
			error.throw_if("NtMapViewOfSection: write relocated image data");
		}
		else
		{
			error = emulator->write_virtual_memory(mapping_address, data.data() + offset, copy_size);
			error.throw_if("NtMapViewOfSection: write file data");
		}
	}

	if (base_address_ptr)
	{
		error = emulator->write_virtual_memory(base_address_ptr, &mapping_address, sizeof(mapping_address));
		error.throw_if("NtMapViewOfSection: write BaseAddress");
	}

	if (view_size_ptr)
	{
		error = emulator->write_virtual_memory(view_size_ptr, &view_size, sizeof(view_size));
		error.throw_if("NtMapViewOfSection: write ViewSize");
	}

	THREAD_LOG("NtMapViewOfSection: mapped 0x{:X} bytes at 0x{:X} (offset=0x{:X}, file_size=0x{:X})",
		view_size, mapping_address, offset, file_size);

	if (section->is_image && kernel::active_process()->peb_address() != 0)
	{
		std::uint32_t e_lfanew = 0;
		(void)emulator->read_virtual_memory(mapping_address + 0x3C, &e_lfanew, sizeof(e_lfanew));

		if (e_lfanew > 0 && e_lfanew < 0x1000)
		{
			std::uint32_t entry_rva = 0;
			(void)emulator->read_virtual_memory(mapping_address + e_lfanew + 0x28, &entry_rva, sizeof(entry_rva));

			if (entry_rva > 0)
			{
				const auto entry_address = mapping_address + entry_rva;
				THREAD_LOG("NtMapViewOfSection: DLL entry point at 0x{:X} (RVA=0x{:X}, base=0x{:X})",
					entry_address, entry_rva, mapping_address);
			}
		}
	}

	if (section->is_image && mapping_address != section->preferred_base)
	{
		constexpr std::uint32_t status_image_not_at_base = 0x40000003;
		THREAD_LOG("NtMapViewOfSection: image not at preferred base (0x{:X} vs 0x{:X}), returning STATUS_IMAGE_NOT_AT_BASE",
			mapping_address, section->preferred_base);
		write_nt_status(emulator, status_image_not_at_base);
	}
	else
	{
		write_nt_success(emulator);
	}
}

static void handle_unmap_view_of_section(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type process_handle, emulator_t::address_type base_address)
{
	THREAD_LOG("NtUnmapViewOfSection called (process_handle=0x{:X}, base_address=0x{:X})",
		process_handle, base_address);

	// todo: actually free the guest memory mapping

	write_nt_success(emulator);
}

static void handle_unmap_view_in_system_space(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type mapped_base)
{
	THREAD_LOG("MmUnmapViewInSystemSpace called (mapped_base=0x{:X})", mapped_base);

	// todo: actually free the guest memory mapping

	write_nt_success(emulator);
}

static void handle_build_mdl_for_non_paged_pool(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type mdl_address)
{
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
}

static void handle_flush_instruction_cache(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t process_handle, std::uint64_t base_address, std::uint64_t length)
{
	THREAD_LOG("NtFlushInstructionCache called (process=0x{:X}, base=0x{:X}, length=0x{:X})",
		process_handle, base_address, length);

	write_nt_success(emulator);
}

static void handle_flush_process_write_buffers(const std::shared_ptr<emulator_t>& emulator)
{
	THREAD_LOG("NtFlushProcessWriteBuffers called");
	write_nt_success(emulator);
}

void redirect_ntoskrnl_memory_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_allocate_pool_with_tag>(emulator, mapped_image, "ExAllocatePoolWithTag");
	redirect_handler<handle_allocate_pool2>(emulator, mapped_image, "ExAllocatePool2");
	redirect_handler<handle_allocate_pool>(emulator, mapped_image, "ExAllocatePool");
	redirect_handler<handle_free_pool_with_tag>(emulator, mapped_image, "ExFreePoolWithTag");
	redirect_handler<handle_compare_memory>(emulator, mapped_image, "RtlCompareMemory");
	redirect_handler<handle_is_address_valid>(emulator, mapped_image, "MmIsAddressValid");
	redirect_handler<handle_get_system_routine_address>(emulator, mapped_image, "MmGetSystemRoutineAddress");
	redirect_handler<handle_get_physical_memory_ranges>(emulator, mapped_image, "MmGetPhysicalMemoryRanges");
	redirect_handler<handle_allocate_contiguous_memory_specify_cache>(emulator, mapped_image, "MmAllocateContiguousMemorySpecifyCache");
	redirect_handler<handle_allocate_contiguous_node_memory>(emulator, mapped_image, "MmAllocateContiguousNodeMemory");
	redirect_handler<handle_free_contiguous_memory>(emulator, mapped_image, "MmFreeContiguousMemory");

	redirect_handler<handle_map_io_space_ex>(emulator, mapped_image, "MmMapIoSpaceEx");
	redirect_handler<handle_map_io_space_ex>(emulator, mapped_image, "MmMapIoSpace");
	redirect_handler<handle_unmap_io_space>(emulator, mapped_image, "MmUnmapIoSpace");

	redirect_handler<handle_get_physical_address>(emulator, mapped_image, "MmGetPhysicalAddress");
	redirect_handler<handle_get_virtual_for_physical>(emulator, mapped_image, "MmGetVirtualForPhysical");
	redirect_handler<handle_copy_memory>(emulator, mapped_image, "MmCopyMemory");

	redirect_handler<handle_map_io_space>(emulator, mapped_image, "MmMapIoSpace");
	redirect_handler<handle_unmap_io_space_2>(emulator, mapped_image, "MmUnmapIoSpace");

	redirect_handler<handle_allocate_mdl>(emulator, mapped_image, "IoAllocateMdl");
	redirect_handler<handle_free_mdl>(emulator, mapped_image, "IoFreeMdl");

	redirect_handler<handle_mm_create_section>(emulator, mapped_image, "MmCreateSection");

	redirect_handler<handle_create_section>(emulator, mapped_image, "NtCreateSection");
	redirect_handler<handle_create_section>(emulator, mapped_image, "ZwCreateSection");

	redirect_handler<handle_open_section>(emulator, mapped_image, "NtOpenSection");
	redirect_handler<handle_open_section>(emulator, mapped_image, "ZwOpenSection");

	redirect_handler<handle_map_view_in_system_space>(emulator, mapped_image, "MmMapViewInSystemSpace");
	redirect_handler<handle_map_view_of_section>(emulator, mapped_image, "NtMapViewOfSection");
	redirect_handler<handle_unmap_view_of_section>(emulator, mapped_image, "NtUnmapViewOfSection");
	redirect_handler<handle_unmap_view_in_system_space>(emulator, mapped_image, "MmUnmapViewInSystemSpace");
	redirect_handler<handle_build_mdl_for_non_paged_pool>(emulator, mapped_image, "MmBuildMdlForNonPagedPool");

	// NtAllocateVirtualMemory(ProcessHandle, BaseAddress*, ZeroBits, RegionSize*, AllocationType, Protect)
	const auto allocate_virtual_memory = [emulator]
	{
		const auto process_handle = read_raw_arg(emulator, 0);
		const auto base_address_ptr = read_raw_arg(emulator, 1);
		const auto zero_bits = read_raw_arg(emulator, 2);
		const auto region_size_ptr = read_raw_arg(emulator, 3);
		const auto allocation_type = static_cast<std::uint32_t>(read_raw_arg(emulator, 4));
		const auto protection = static_cast<std::uint32_t>(read_raw_arg(emulator, 5));

		emulator_t::address_type base_address = 0;
		emulator_t::size_type region_size = 0;

		if (base_address_ptr)
		{
			static_cast<void>(emulator->read_virtual_memory(base_address_ptr, &base_address, sizeof(base_address)));
		}

		if (region_size_ptr)
		{
			static_cast<void>(emulator->read_virtual_memory(region_size_ptr, &region_size, sizeof(region_size)));
		}

		THREAD_LOG("NtAllocateVirtualMemory called (process=0x{:X}, base=0x{:X}, size=0x{:X}, type=0x{:X}, prot=0x{:X})",
			process_handle, base_address, region_size, allocation_type, protection);

		if (!user::memory_manager)
		{
			const auto alloc = emulator->heap_allocate(region_size, prot_read_write, true);

			if (alloc)
			{
				base_address = *alloc;

				if (base_address_ptr)
				{
					static_cast<void>(emulator->write_virtual_memory(base_address_ptr, &base_address, sizeof(base_address)));
				}

				if (region_size_ptr)
				{
					const auto aligned = (region_size + 0xFFF) & ~static_cast<emulator_t::size_type>(0xFFF);
					static_cast<void>(emulator->write_virtual_memory(region_size_ptr, &aligned, sizeof(aligned)));
				}

				write_nt_success(emulator);
			}
			else
			{
				write_nt_status(emulator, 0xC0000017); // STATUS_NO_MEMORY
			}

			return;
		}

		const auto status = user::memory_manager->allocate(base_address, region_size, allocation_type, protection);

		if (base_address_ptr)
		{
			static_cast<void>(emulator->write_virtual_memory(base_address_ptr, &base_address, sizeof(base_address)));
		}

		if (region_size_ptr)
		{
			static_cast<void>(emulator->write_virtual_memory(region_size_ptr, &region_size, sizeof(region_size)));
		}

		THREAD_LOG("NtAllocateVirtualMemory -> base=0x{:X}, size=0x{:X}, status=0x{:X}",
			base_address, region_size, status);

		write_nt_status(emulator, status);
	};

	redirect_function(allocate_virtual_memory, mapped_image, "NtAllocateVirtualMemory");
	redirect_function(allocate_virtual_memory, mapped_image, "ZwAllocateVirtualMemory");

	// NtAllocateVirtualMemoryEx(ProcessHandle, BaseAddress*, RegionSize*, AllocationType, PageProtection, ExtendedParameters*, ExtendedParameterCount)
	const auto allocate_virtual_memory_ex = [emulator]
	{
		const auto process_handle = read_raw_arg(emulator, 0);
		const auto base_address_ptr = read_raw_arg(emulator, 1);
		const auto region_size_ptr = read_raw_arg(emulator, 2);
		const auto allocation_type = static_cast<std::uint32_t>(read_raw_arg(emulator, 3));
		const auto protection = static_cast<std::uint32_t>(read_raw_arg(emulator, 4));
		const auto extended_params = read_raw_arg(emulator, 5);
		const auto extended_param_count = static_cast<std::uint32_t>(read_raw_arg(emulator, 6));

		emulator_t::address_type base_address = 0;
		emulator_t::size_type region_size = 0;

		if (base_address_ptr)
		{
			static_cast<void>(emulator->read_virtual_memory(base_address_ptr, &base_address, sizeof(base_address)));
		}

		if (region_size_ptr)
		{
			static_cast<void>(emulator->read_virtual_memory(region_size_ptr, &region_size, sizeof(region_size)));
		}

		// parse MEM_EXTENDED_PARAMETER for alignment requirements
		emulator_t::size_type requested_alignment = 0;

		if (extended_params && extended_param_count > 0)
		{
			for (std::uint32_t i = 0; i < extended_param_count; ++i)
			{
				struct mem_extended_parameter_t
				{
					std::uint64_t type_and_reserved;
					std::uint64_t value;
				};

				mem_extended_parameter_t param{};
				const auto param_addr = extended_params + i * sizeof(param);
				static_cast<void>(emulator->read_virtual_memory(param_addr, &param, sizeof(param)));

				const auto param_type = param.type_and_reserved & 0xFF;

				if (param_type == 1) // MemExtendedParameterAddressRequirements
				{
					struct mem_address_requirements_t
					{
						std::uint64_t lowest_starting_address;
						std::uint64_t highest_ending_address;
						std::uint64_t alignment;
					};

					mem_address_requirements_t reqs{};
					static_cast<void>(emulator->read_virtual_memory(param.value, &reqs, sizeof(reqs)));

					requested_alignment = reqs.alignment;

					THREAD_LOG("NtAllocateVirtualMemoryEx: address requirements (lowest=0x{:X}, highest=0x{:X}, alignment=0x{:X})",
						reqs.lowest_starting_address, reqs.highest_ending_address, reqs.alignment);
				}
			}
		}

		THREAD_LOG("NtAllocateVirtualMemoryEx called (process=0x{:X}, base=0x{:X}, size=0x{:X}, type=0x{:X}, prot=0x{:X}, ext_params=0x{:X}, ext_count={})",
			process_handle, base_address, region_size, allocation_type, protection, extended_params, extended_param_count);

		if (!user::memory_manager)
		{
			const auto alloc = emulator->heap_allocate(region_size, prot_read_write, true);

			if (alloc)
			{
				base_address = *alloc;

				if (base_address_ptr)
				{
					static_cast<void>(emulator->write_virtual_memory(base_address_ptr, &base_address, sizeof(base_address)));
				}

				if (region_size_ptr)
				{
					const auto aligned = (region_size + 0xFFF) & ~static_cast<emulator_t::size_type>(0xFFF);
					static_cast<void>(emulator->write_virtual_memory(region_size_ptr, &aligned, sizeof(aligned)));
				}

				write_nt_success(emulator);
			}
			else
			{
				write_nt_status(emulator, 0xC0000017); // STATUS_NO_MEMORY
			}

			return;
		}

		const auto status = user::memory_manager->allocate(base_address, region_size, allocation_type, protection, requested_alignment);

		if (base_address_ptr)
		{
			static_cast<void>(emulator->write_virtual_memory(base_address_ptr, &base_address, sizeof(base_address)));
		}

		if (region_size_ptr)
		{
			static_cast<void>(emulator->write_virtual_memory(region_size_ptr, &region_size, sizeof(region_size)));
		}

		THREAD_LOG("NtAllocateVirtualMemoryEx -> base=0x{:X}, size=0x{:X}, status=0x{:X}",
			base_address, region_size, status);

		write_nt_status(emulator, status);
	};

	redirect_function(allocate_virtual_memory_ex, mapped_image, "NtAllocateVirtualMemoryEx");
	redirect_function(allocate_virtual_memory_ex, mapped_image, "ZwAllocateVirtualMemoryEx");

	// NtFreeVirtualMemory(ProcessHandle, BaseAddress*, RegionSize*, FreeType)
	const auto free_virtual_memory = [emulator]
	{
		const auto process_handle = read_raw_arg(emulator, 0);
		const auto base_address_ptr = read_raw_arg(emulator, 1);
		const auto region_size_ptr = read_raw_arg(emulator, 2);
		const auto free_type = static_cast<std::uint32_t>(read_raw_arg(emulator, 3));

		emulator_t::address_type base_address = 0;
		emulator_t::size_type region_size = 0;

		if (base_address_ptr)
		{
			static_cast<void>(emulator->read_virtual_memory(base_address_ptr, &base_address, sizeof(base_address)));
		}

		if (region_size_ptr)
		{
			static_cast<void>(emulator->read_virtual_memory(region_size_ptr, &region_size, sizeof(region_size)));
		}

		THREAD_LOG("NtFreeVirtualMemory called (process=0x{:X}, base=0x{:X}, size=0x{:X}, type=0x{:X})",
			process_handle, base_address, region_size, free_type);

		if (!user::memory_manager)
		{
			write_nt_success(emulator);
			return;
		}

		const auto status = user::memory_manager->free(base_address, region_size, free_type);

		if (status == 0)
		{
			if (base_address_ptr)
			{
				static_cast<void>(emulator->write_virtual_memory(base_address_ptr, &base_address, sizeof(base_address)));
			}

			if (region_size_ptr)
			{
				static_cast<void>(emulator->write_virtual_memory(region_size_ptr, &region_size, sizeof(region_size)));
			}
		}

		write_nt_status(emulator, status);
	};

	redirect_function(free_virtual_memory, mapped_image, "NtFreeVirtualMemory");
	redirect_function(free_virtual_memory, mapped_image, "ZwFreeVirtualMemory");

	// NtProtectVirtualMemory(ProcessHandle, BaseAddress*, RegionSize*, NewProtect, OldProtect*)
	const auto protect_virtual_memory = [emulator]
	{
		const auto process_handle = read_raw_arg(emulator, 0);
		const auto base_address_ptr = read_raw_arg(emulator, 1);
		const auto region_size_ptr = read_raw_arg(emulator, 2);
		const auto new_protection = static_cast<std::uint32_t>(read_raw_arg(emulator, 3));
		const auto old_protection_ptr = read_raw_arg(emulator, 4);

		emulator_t::address_type base_address = 0;
		emulator_t::size_type region_size = 0;

		if (base_address_ptr)
		{
			static_cast<void>(emulator->read_virtual_memory(base_address_ptr, &base_address, sizeof(base_address)));
		}

		if (region_size_ptr)
		{
			static_cast<void>(emulator->read_virtual_memory(region_size_ptr, &region_size, sizeof(region_size)));
		}

		THREAD_LOG("NtProtectVirtualMemory called (process=0x{:X}, base=0x{:X}, size=0x{:X}, new_prot=0x{:X})",
			process_handle, base_address, region_size, new_protection);

		std::uint32_t old_protection = user::page_readwrite;

		if (user::memory_manager)
		{
			const auto status = user::memory_manager->protect(base_address, region_size, new_protection, old_protection);

			if (base_address_ptr)
			{
				static_cast<void>(emulator->write_virtual_memory(base_address_ptr, &base_address, sizeof(base_address)));
			}

			if (region_size_ptr)
			{
				static_cast<void>(emulator->write_virtual_memory(region_size_ptr, &region_size, sizeof(region_size)));
			}

			if (old_protection_ptr)
			{
				static_cast<void>(emulator->write_virtual_memory(old_protection_ptr, &old_protection, sizeof(old_protection)));
			}

			write_nt_status(emulator, status);
		}
		else
		{
			if (old_protection_ptr)
			{
				static_cast<void>(emulator->write_virtual_memory(old_protection_ptr, &old_protection, sizeof(old_protection)));
			}

			write_nt_success(emulator);
		}
	};

	redirect_function(protect_virtual_memory, mapped_image, "NtProtectVirtualMemory");
	redirect_function(protect_virtual_memory, mapped_image, "ZwProtectVirtualMemory");

	// NtQueryVirtualMemory(ProcessHandle, BaseAddress, InfoClass, Buffer, Length, ReturnLength*)
	const auto query_virtual_memory = [emulator]
	{
		const auto process_handle = read_raw_arg(emulator, 0);
		const auto base_address = read_raw_arg(emulator, 1);
		const auto info_class = static_cast<std::uint32_t>(read_raw_arg(emulator, 2));
		const auto buffer_address = read_raw_arg(emulator, 3);
		const auto buffer_length = static_cast<std::uint32_t>(read_raw_arg(emulator, 4));
		const auto return_length_ptr = read_raw_arg(emulator, 5);

		THREAD_LOG("NtQueryVirtualMemory called (process=0x{:X}, base=0x{:X}, class=0x{:X}, buf=0x{:X}, len=0x{:X})",
			process_handle, base_address, info_class, buffer_address, buffer_length);

		constexpr std::uint32_t memory_basic_information_class = 0;
		constexpr std::uint32_t memory_working_set_ex_class = 4;
		constexpr std::uint32_t memory_image_information_class = 6;
		constexpr std::uint32_t memory_region_information_class = 9;

		if (info_class == memory_basic_information_class)
		{
			user::memory_basic_information_t info = {};
			constexpr std::uint32_t info_size = sizeof(info);

			if (buffer_length < info_size)
			{
				if (return_length_ptr)
				{
					static_cast<void>(emulator->write_virtual_memory(return_length_ptr, &info_size, sizeof(info_size)));
				}

				write_nt_status(emulator, 0xC0000004); // STATUS_INFO_LENGTH_MISMATCH
				return;
			}

			if (user::memory_manager)
			{
				user::memory_manager->query_basic(base_address, info);
			}
			else
			{
				info.base_address = base_address & ~static_cast<std::uint64_t>(0xFFF);
				info.region_size = 0x1000;
				info.state = user::mem_free;
				info.protect = user::page_noaccess;
			}

			static_cast<void>(emulator->write_virtual_memory(buffer_address, &info, info_size));

			if (return_length_ptr)
			{
				static_cast<void>(emulator->write_virtual_memory(return_length_ptr, &info_size, sizeof(info_size)));
			}

			THREAD_LOG("NtQueryVirtualMemory: basic info for 0x{:X} -> state=0x{:X}, prot=0x{:X}, size=0x{:X}, type=0x{:X}",
				base_address, info.state, info.protect, info.region_size, info.type);

			write_nt_success(emulator);
		}
		else if (info_class == memory_working_set_ex_class)
		{
			THREAD_LOG("NtQueryVirtualMemory: working set ex -> STATUS_NOT_SUPPORTED");
			write_nt_status(emulator, 0xC00000BB); // STATUS_NOT_SUPPORTED
		}
		else if (info_class == memory_image_information_class)
		{
			if (base_address >= 0x00007FFFFFFF0000ULL)
			{
				THREAD_LOG("NtQueryVirtualMemory: class 6 invalid base 0x{:X} -> STATUS_INVALID_PARAMETER", base_address);
				write_nt_status(emulator, 0xC000000D); // STATUS_INVALID_PARAMETER
				return;
			}

			// MEMORY_IMAGE_INFORMATION: ImageBase(8), SizeOfImage(8), ImageFlags(4)
			struct
			{
				std::uint64_t image_base;
				std::uint64_t size_of_image;
				std::uint32_t image_flags;
			} image_info = {};

			if (user::memory_manager)
			{
				user::memory_basic_information_t basic = {};
				user::memory_manager->query_basic(base_address, basic);

				if (basic.type == user::mem_image)
				{
					image_info.image_base = basic.allocation_base;
					image_info.size_of_image = basic.region_size;
					image_info.image_flags = 0;
				}
			}

			const auto write_size = std::min(static_cast<std::size_t>(buffer_length), sizeof(image_info));

			if (buffer_address && write_size)
			{
				static_cast<void>(emulator->write_virtual_memory(buffer_address, &image_info, write_size));
			}

			if (return_length_ptr)
			{
				const auto ret_len = static_cast<std::uint32_t>(sizeof(image_info));
				static_cast<void>(emulator->write_virtual_memory(return_length_ptr, &ret_len, sizeof(ret_len)));
			}

			write_nt_success(emulator);
		}
		else if (info_class == memory_region_information_class)
		{
			// MEMORY_REGION_INFORMATION
			struct
			{
				std::uint64_t allocation_base;
				std::uint32_t allocation_protect;
				std::uint32_t padding;
				std::uint64_t region_size;
				std::uint64_t commit_size;
			} region_info = {};

			if (user::memory_manager)
			{
				user::memory_basic_information_t basic = {};
				user::memory_manager->query_basic(base_address, basic);

				region_info.allocation_base = basic.allocation_base;
				region_info.allocation_protect = basic.allocation_protect;
				region_info.region_size = basic.region_size;
				region_info.commit_size = (basic.state == user::mem_commit) ? basic.region_size : 0;
			}

			const auto write_size = std::min(static_cast<std::size_t>(buffer_length), sizeof(region_info));

			if (buffer_address && write_size)
			{
				static_cast<void>(emulator->write_virtual_memory(buffer_address, &region_info, write_size));
			}

			if (return_length_ptr)
			{
				const auto ret_len = static_cast<std::uint32_t>(sizeof(region_info));
				static_cast<void>(emulator->write_virtual_memory(return_length_ptr, &ret_len, sizeof(ret_len)));
			}

			write_nt_success(emulator);
		}
		else
		{
			THREAD_WARN_LOG("NtQueryVirtualMemory: unhandled class 0x{:X}", info_class);
			write_nt_status(emulator, 0xC0000003); // STATUS_INVALID_INFO_CLASS
		}
	};

	redirect_function(query_virtual_memory, mapped_image, "NtQueryVirtualMemory");
	redirect_function(query_virtual_memory, mapped_image, "ZwQueryVirtualMemory");

	// NtFlushInstructionCache(ProcessHandle, BaseAddress, Length)
	redirect_handler<handle_flush_instruction_cache>(emulator, mapped_image, "NtFlushInstructionCache");

	// NtFlushProcessWriteBuffers()
	redirect_handler<handle_flush_process_write_buffers>(emulator, mapped_image, "NtFlushProcessWriteBuffers");

	// NtQuerySection(Handle, SectionInformationClass, SectionInformation, SectionInformationLength, ReturnLength*)
	// classes: 0=SectionBasicInformation (24 bytes), 1=SectionImageInformation (64 bytes),
	//          2=SectionRelocationInformation (8 bytes), 3=SectionOriginalBaseInformation (8 bytes)
	const auto query_section_handler = [emulator]
	{
		const auto section_handle = read_raw_arg(emulator, 0);
		const auto info_class = static_cast<std::uint32_t>(read_raw_arg(emulator, 1));
		const auto buffer_address = read_raw_arg(emulator, 2);
		const auto buffer_length = static_cast<std::uint32_t>(read_raw_arg(emulator, 3));
		const auto return_length_ptr = read_raw_arg(emulator, 4);

		THREAD_LOG("NtQuerySection called (handle=0x{:X}, class={}, buf=0x{:X}, len=0x{:X})",
			section_handle, info_class, buffer_address, buffer_length);

		constexpr std::uint32_t status_invalid_handle = 0xC0000008;
		constexpr std::uint32_t status_info_length_mismatch = 0xC0000004;
		constexpr std::uint32_t status_invalid_info_class = 0xC0000003;
		constexpr std::uint32_t status_section_not_image = 0xC0000048;

		std::uint32_t required_size = 0;

		switch (info_class)
		{
		case 0:
			required_size = 24;
			break;
		case 1:
			required_size = 64;
			break;
		case 2:
		case 3:
			required_size = 8;
			break;
		default:
			THREAD_WARN_LOG("NtQuerySection: unsupported class {}", info_class);
			write_nt_status(emulator, status_invalid_info_class);
			return;
		}

		if (buffer_length < required_size)
		{
			if (return_length_ptr)
			{
				static_cast<void>(emulator->write_virtual_memory(return_length_ptr, &required_size, sizeof(required_size)));
			}

			write_nt_status(emulator, status_info_length_mismatch);
			return;
		}

		const auto section = kernel::active_handle_table().get_object_from_handle<section_object_t>(section_handle);

		if (!section)
		{
			THREAD_WARN_LOG("NtQuerySection: invalid handle 0x{:X}", section_handle);
			write_nt_status(emulator, status_invalid_handle);
			return;
		}

		if (info_class == 0)
		{
			// SectionBasicInformation: BaseAddress (8), AllocationAttributes (4), padding (4), MaximumSize (8)
			struct section_basic_information_t
			{
				std::uint64_t base_address;
				std::uint32_t allocation_attributes;
				std::uint32_t padding;
				std::int64_t maximum_size;
			};

			static_assert(sizeof(section_basic_information_t) == 24);

			std::uint32_t attrs = 0;

			if (section->is_image)
			{
				attrs = sec_image;
			}
			else
			{
				attrs = 0x4000000; // SEC_COMMIT
			}

			std::int64_t size = 0;

			if (section->file)
			{
				size = static_cast<std::int64_t>(section->file->size());
			}

			section_basic_information_t info = { };
			info.base_address = 0;
			info.allocation_attributes = attrs;
			info.maximum_size = size;

			const emulator_err_t error = emulator->write_virtual_memory(buffer_address, &info, sizeof(info));
			error.throw_if("NtQuerySection: write SectionBasicInformation");

			if (return_length_ptr)
			{
				static_cast<void>(emulator->write_virtual_memory(return_length_ptr, &required_size, sizeof(required_size)));
			}

			THREAD_LOG("NtQuerySection: basic info -> attrs=0x{:X}, size=0x{:X}", attrs, size);

			write_nt_success(emulator);
			return;
		}

		if (info_class == 1)
		{
			// SectionImageInformation (64 bytes) - only valid for SEC_IMAGE sections
			if (!section->is_image)
			{
				THREAD_WARN_LOG("NtQuerySection: class 1 on non-image section");
				write_nt_status(emulator, status_section_not_image);
				return;
			}

			// parsed from the PE header in the backing file
			struct section_image_information_t
			{
				std::uint64_t transfer_address;
				std::uint32_t zero_bits;
				std::uint32_t padding0;
				std::uint64_t maximum_stack_size;
				std::uint64_t committed_stack_size;
				std::uint32_t sub_system_type;
				std::uint16_t sub_system_minor_version;
				std::uint16_t sub_system_major_version;
				std::uint32_t gp_value;
				std::uint16_t image_characteristics;
				std::uint16_t dll_characteristics;
				std::uint16_t machine;
				std::uint8_t image_contains_code;
				std::uint8_t image_flags;
				std::uint32_t loader_flags;
				std::uint32_t image_file_size;
				std::uint32_t check_sum;
			};

			static_assert(sizeof(section_image_information_t) == 64);

			section_image_information_t info = { };

			if (section->file)
			{
				const auto data = section->file->read();

				if (data.size() >= sizeof(portable_executable::dos_header_t))
				{
					const auto* pe = reinterpret_cast<const portable_executable::image_t*>(data.data());
					const auto* dos = pe->dos_header();

					if (dos->valid())
					{
						const auto* nt = pe->nt_headers();
						const auto& opt = nt->optional_header;

						info.transfer_address = opt.image_base + opt.address_of_entry_point;
						info.maximum_stack_size = opt.size_of_stack_reserve;
						info.committed_stack_size = opt.size_of_stack_commit;
						info.sub_system_type = opt.subsystem;
						info.sub_system_minor_version = opt.minor_subsystem_version;
						info.sub_system_major_version = opt.major_subsystem_version;
						info.image_characteristics = nt->file_header.characteristics;
						info.dll_characteristics = opt.dll_characteristics;
						info.machine = nt->file_header.machine;
						info.image_contains_code = (opt.size_of_code > 0) ? 1 : 0;
						info.loader_flags = opt.loader_flags;
						info.check_sum = opt.check_sum;
						info.image_file_size = static_cast<std::uint32_t>(data.size());
					}
				}
			}

			const emulator_err_t error = emulator->write_virtual_memory(buffer_address, &info, sizeof(info));
			error.throw_if("NtQuerySection: write SectionImageInformation");

			if (return_length_ptr)
			{
				static_cast<void>(emulator->write_virtual_memory(return_length_ptr, &required_size, sizeof(required_size)));
			}

			THREAD_LOG("NtQuerySection: image info -> transfer=0x{:X}, machine=0x{:X}, subsystem={}",
				info.transfer_address, info.machine, info.sub_system_type);

			write_nt_success(emulator);
			return;
		}

		// class 2 (SectionRelocationInformation) and class 3 (SectionOriginalBaseInformation) - return preferred base
		std::int64_t value = static_cast<std::int64_t>(section->preferred_base);

		const emulator_err_t error = emulator->write_virtual_memory(buffer_address, &value, sizeof(value));
		error.throw_if("NtQuerySection: write relocation/original base");

		if (return_length_ptr)
		{
			static_cast<void>(emulator->write_virtual_memory(return_length_ptr, &required_size, sizeof(required_size)));
		}

		THREAD_LOG("NtQuerySection: class {} -> value=0x{:X}", info_class, value);

		write_nt_success(emulator);
	};

	redirect_function(query_section_handler, mapped_image, "NtQuerySection");
	redirect_function(query_section_handler, mapped_image, "ZwQuerySection");
}
