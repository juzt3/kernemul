#include <algorithm>
#include <ranges>

#include "emulator.hpp"
#include <ia32-doc/ia32.hpp>

constexpr emulator_t::size_type paging_table_size = 0x1000;
constexpr emulator_t::size_type paging_entry_count = 512;

emulator_err_t emulator_t::read_physical_memory(const address_type address, const std::span<std::uint8_t> buffer) const
{
	return read_physical_memory(address, buffer.data(), buffer.size());
}

emulator_err_t emulator_t::write_physical_memory(const address_type address, const std::span<const std::uint8_t> buffer)
{
	return write_physical_memory(address, buffer.data(), buffer.size());
}

emulator_err_t emulator_t::copy_virtual_memory(const address_type address, void* const buffer, const size_type size,
                                               const bool is_write)
{
	size_type count = 0;

	while (count < size)
	{
		const address_type current_virtual_address = address + count;

		const auto current_physical_address = translate_virtual_address(current_virtual_address);

		if (!current_physical_address)
		{
			return emulator_err_t{ false };
		}

		const size_type page_offset = current_virtual_address % page_size;

		const size_type size_remain = size - count;
		const size_type page_remain = page_size - page_offset;

		if (!page_remain)
		{
			return emulator_err_t{ false };
		}

		const size_type current_size = std::min(page_remain, size_remain);
		const auto current_buffer = static_cast<std::uint8_t*>(buffer) + count;

		const emulator_err_t error = is_write
			                             ? write_physical_memory(*current_physical_address, current_buffer, current_size)
			                             : read_physical_memory(*current_physical_address, current_buffer, current_size);

		if (error)
		{
			return error;
		}

		count += current_size;
	}

	return emulator_err_t{ count == size };
}

emulator_err_t emulator_t::map_virtual_memory(const address_type address, const size_type size,
                                              const protection_type protection)
{
	const auto physical_allocation = allocate_physical_memory(size, protection);

	if (!physical_allocation)
	{
		return physical_allocation.error();
	}

	for (size_type i = 0; i < size; i += page_size)
	{
		if (const auto error = map_virtual_page(address + i, *physical_allocation + i))
		{
			return error;
		}
	}

	return emulator_err_t{ };
}

emulator_err_t emulator_t::unmap_virtual_memory(const address_type address, const size_type size)
{
	for (size_type i = 0; i < size; i += page_size)
	{
		if (const auto error = unmap_virtual_page(address + i))
		{
			return error;
		}
	}

	return emulator_err_t{ };
}

emulator_err_t emulator_t::write_virtual_memory(const address_type address, const void* const buffer,
                                                const size_type size)
{
	return copy_virtual_memory(address, const_cast<void*>(buffer), size, true);
}

emulator_err_t emulator_t::write_virtual_memory(const address_type address, const std::span<const std::uint8_t> buffer)
{
	return write_virtual_memory(address, buffer.data(), buffer.size());
}

emulator_err_t emulator_t::read_virtual_memory(const address_type address, void* const buffer,
                                               const size_type size) const
{
	return const_cast<emulator_t*>(this)->copy_virtual_memory(address, buffer, size, false);
}

emulator_err_t emulator_t::read_virtual_memory(const address_type address, const std::span<std::uint8_t> buffer) const
{
	return read_virtual_memory(address, buffer.data(), buffer.size());
}

emulator_err_t emulator_t::load_physical_memory(const address_type address, const std::span<const std::uint8_t> buffer,
                                                const protection_type protection)
{
	emulator_err_t error = map_physical_memory(address, buffer.size(), protection);

	if (error)
	{
		return error;
	}

	error = write_physical_memory(address, buffer);

	if (error)
	{
		(void)unmap_physical_memory(address, buffer.size());
	}

	return error;
}

emulator_err_t emulator_t::load_virtual_memory(const address_type address, const std::span<const std::uint8_t> buffer,
                                               const protection_type protection)
{
	const address_type aligned_address = align_down(address, page_size);
	const size_type aligned_size = align_up(buffer.size(), page_size);

	emulator_err_t error = map_virtual_memory(aligned_address, aligned_size, protection);

	if (error)
	{
		return error;
	}

	error = write_virtual_memory(address, buffer);

	if (error)
	{
		(void)unmap_virtual_memory(address, buffer.size());
	}

	return error;
}

std::optional<emulator_t::address_type> emulator_t::translate_virtual_address(const address_type address)
{
	const address_type aligned_page_address = align_down(address, page_size);

	const auto it = virtual_page_mappings_.find(aligned_page_address);

	if (it == virtual_page_mappings_.end())
	{
		return { };
	}

	const auto& mapping = it->second;

	const paging_virtual_address_t virtual_address = {
		.address = address
	};

	return mapping.physical_address + virtual_address.page_offset;
}

std::optional<emulator_t::address_type> emulator_t::translate_physical_address(const address_type physical_address) const
{
	const address_type aligned_physical = align_down(physical_address, page_size);
	const address_type page_offset = physical_address - aligned_physical;

	for (const auto& [virtual_page, mapping] : virtual_page_mappings_)
	{
		if (mapping.physical_address == aligned_physical)
		{
			return virtual_page + page_offset;
		}
	}

	return { };
}

bool emulator_t::is_physical_address_valid(const address_type physical_address) const
{
	const address_type aligned_physical = align_down(physical_address, page_size);

	for (const auto& mapping : virtual_page_mappings_ | std::views::values)
	{
		if (mapping.physical_address == aligned_physical)
		{
			return true;
		}
	}

	return false;
}

std::vector<physical_memory_range_t> emulator_t::physical_memory_ranges() const
{
	// todo: include page table entry allocations in here

	std::vector<std::uint64_t> physical_pages(virtual_page_mappings_.size());

	for (const auto& mapping : virtual_page_mappings_ | std::views::values)
	{
		physical_pages.push_back(mapping.physical_address);
	}

	std::ranges::sort(physical_pages);

	const auto unique_end = std::ranges::unique(physical_pages);
	physical_pages.erase(unique_end.begin(), unique_end.end());

	std::vector<physical_memory_range_t> ranges;

	if (physical_pages.empty())
	{
		return ranges;
	}

	auto current_start = physical_pages[0];
	auto current_size = static_cast<std::uint64_t>(page_size);

	for (std::size_t i = 1; i < physical_pages.size(); ++i)
	{
		if (physical_pages[i] == current_start + current_size)
		{
			current_size += page_size;
		}
		else
		{
			ranges.emplace_back(current_start, current_size);

			current_start = physical_pages[i];
			current_size = page_size;
		}
	}

	ranges.emplace_back(current_start, current_size);

	return ranges;
}

std::expected<emulator_t::address_type, emulator_err_t> emulator_t::heap_allocate(
	const size_type size, const protection_type protection, const bool page_aligned)
{
	if (last_heap_protection_ == prot_none || last_heap_protection_ != protection ||
		page_aligned)
	{
		current_heap_virtual_address_ = align_up(current_heap_virtual_address_, page_size);
	}

	size_type size_left_of_allocation = size;
	address_type current_address = current_heap_virtual_address_;

	do
	{
		const size_type size_left_of_page = page_size - (current_address % page_size);
		const size_type current_size = std::min(size_left_of_allocation, size_left_of_page);

		if (!translate_virtual_address(current_address))
		{
			if (const auto error = map_virtual_memory(current_address, current_size, protection))
			{
				return std::unexpected(error);
			}
		}

		current_address += current_size;
		size_left_of_allocation -= current_size;

	} while (size_left_of_allocation);

	const address_type address = current_heap_virtual_address_;

	current_heap_virtual_address_ += size;
	last_heap_protection_ = protection;

	return address;
}

std::expected<emulator_t::address_type, emulator_err_t> emulator_t::allocate_physical_memory(
	const size_type size, const protection_type protection)
{
	const size_type aligned_size = align_up(size, page_size);
	const address_type address = current_physical_page_;

	if (const auto error = map_physical_memory(address, size, protection))
	{
		return std::unexpected(error);
	}

	current_physical_page_ += aligned_size;

	return address;
}

emulator_err_t emulator_t::map_virtual_page(const address_type page_address, const address_type page_physical_address)
{
#define SETUP_PAGING_LEVEL(previous_level, level) \
		previous_level##e_64& previous_level##e = (previous_level)[virtual_address.previous_level##_index];\
		\
		std::array<level##e_64, paging_entry_count> (level) = { };\
		\
		address_type level##_address = previous_level##e.page_frame_number << 12;\
		\
		if (!previous_level##e.present)\
		{\
			const auto allocation = allocate_physical_memory(paging_table_size, prot_read_write);\
			\
			if (!allocation)\
			{\
				return allocation.error();\
			}\
			\
			previous_level##e.present = 1;\
			previous_level##e.write = 1;\
			previous_level##e.page_frame_number = *allocation >> 12;\
			\
			if (const auto error = write_physical_memory(previous_level##_address, (previous_level).data(), sizeof(previous_level)))\
			{\
				return error;\
			}\
			\
			level##_address = *allocation;\
		}\
		else\
		{\
			if (const auto error = read_physical_memory(level##_address, (level).data(), sizeof(level)))\
			{\
				return error;\
			}\
		}

	const address_type aligned_page_address = align_down(page_address, page_size);
	const address_type aligned_page_physical_address = align_down(page_physical_address, page_size);

	virtual_page_mappings_[aligned_page_address] = virtual_memory_mapping_t{ aligned_page_physical_address };

	std::array<pml4e_64, paging_entry_count> pml4 = { };

	const address_type pml4_address = pml4_physical_address_;

	if (const auto error = read_physical_memory(pml4_address, pml4.data(), sizeof(pml4)))
	{
		return error;
	}

	const paging_virtual_address_t virtual_address = {
		.address = aligned_page_address
	};

	SETUP_PAGING_LEVEL(pml4, pdpt)
	SETUP_PAGING_LEVEL(pdpt, pd)
	SETUP_PAGING_LEVEL(pd, pt)

	pte_64& pte = pt[virtual_address.pt_index];

	pte.present = 1;
	pte.write = 1;
	pte.page_frame_number = aligned_page_physical_address >> 12;

	if (const auto error = write_physical_memory(pt_address, pt.data(), sizeof(pt)))
	{
		return error;
	}

	return emulator_err_t{ };
}

emulator_err_t emulator_t::unmap_virtual_page(const address_type page_address)
{
#define READ_PAGING_ENTRY(level_address, level)\
	level##e_64 level##e = { };\
	const size_type level##e_offset = (virtual_address).level##_index * sizeof(level##e_64);\
	\
	if (read_physical_memory((level_address) + level##e_offset, &level##e, sizeof(level##e_64)) ||\
		!level##e.present)\
	{\
		return { };\
	}

#define WRITE_PAGING_ENTRY(level_address, level)\
	if (write_physical_memory((level_address) + level##e_offset, &level##e, sizeof(level##e_64)))\
	{\
		return { };\
	}

	const auto it = virtual_page_mappings_.find(page_address);

	if (it == virtual_page_mappings_.end())
	{
		return emulator_err_t{ false };
	}

	const paging_virtual_address_t virtual_address = {
		.address = page_address
	};

	READ_PAGING_ENTRY(pml4_physical_address_, pml4)
	READ_PAGING_ENTRY(pml4e.page_frame_number << 12, pdpt)
	READ_PAGING_ENTRY(pdpte.page_frame_number << 12, pd)
	READ_PAGING_ENTRY(pde.page_frame_number << 12, pt)

	pte.flags = 0;

	WRITE_PAGING_ENTRY(pde.page_frame_number << 12, pt)

	virtual_page_mappings_.erase(it);

	return emulator_err_t{ true };
}

emulator_err_t emulator_t::set_up_page_tables()
{
	const auto pml4_allocation = allocate_physical_memory(paging_table_size, prot_all);

	if (!pml4_allocation)
	{
		return pml4_allocation.error();
	}

	std::array<pml4e_64, paging_entry_count> pml4 = { };

	// self-referencing PML4 entry at index 0x1E1 - maps the page table hierarchy
	// into virtual address space so the guest can read/write PTEs directly
	constexpr std::uint16_t pte_self_ref_index = 0x1E1;
	pml4[pte_self_ref_index].present = 1;
	pml4[pte_self_ref_index].write = 1;
	pml4[pte_self_ref_index].page_frame_number = *pml4_allocation >> 12;

	if (const auto error = write_physical_memory(*pml4_allocation, pml4.data(), sizeof(pml4)))
	{
		return error;
	}

	pml4_physical_address_ = *pml4_allocation;

	write_register<x86::reg::cr3>(pml4_physical_address_);

	return emulator_err_t{ };
}
