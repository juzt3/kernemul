#include "nt_mem_ops.hpp"
#include "../win_kernel.hpp"
#include "../mdl.hpp"
#include "../objects.hpp"
#include "../pool.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../map.hpp"
#include "../../../util/log.hpp"
#include <algorithm>
#include <span>
#include <array>
#include <cstring>
#include <vector>
#include <string_view>

namespace
{

constexpr std::uint32_t mm_copy_memory_physical = 0x1;
constexpr std::uint32_t mm_copy_memory_virtual = 0x2;

// There is one kind of memory behind every mapping here, so the type only reaches the log.
std::string_view caching_type_name(const std::uint32_t type)
{
	switch (type)
	{
	case 0:  return "NonCached";
	case 1:  return "Cached";
	case 2:  return "WriteCombined";
	case 3:  return "HardwareCoherentCached";
	case 4:  return "NonCachedUnordered";
	case 5:  return "USWCCached";
	default: return "?";
	}
}


}

// The page tables the mmu walks are the guest's own, not a shadow of the guest's.
void modules::register_ntoskrnl_mem_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "MmIsAddressValid",
		[](vcpu& cpu, const addr_t virtual_address) -> bool
		{
			auto& space = *cpu.curr_addr_space();
			const bool valid = space.mmu_->virt_to_phys(space, virtual_address).has_value();

			THREAD_LOG_INFO("MmIsAddressValid(0x{:X}) -> {}", virtual_address, valid);

			return valid;
		});

	state.redirect(mod, "MmGetPhysicalAddress",
		[](vcpu& cpu, const addr_t base_address) -> std::uint64_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto pa = space.mmu_->virt_to_phys(space, base_address).value_or(0);

			if (!pa)
				THREAD_LOG_WARN("MmGetPhysicalAddress: 0x{:X} is not mapped", base_address);
			else
				THREAD_LOG_INFO("MmGetPhysicalAddress(0x{:X}) -> 0x{:X}", base_address, pa);

			return pa;
		});

	// Real NT reads it out of the PFN database; here the search reaches whichever mapping is first.
	state.redirect(mod, "MmGetVirtualForPhysical",
		[](vcpu& cpu, const std::uint64_t physical_address) -> addr_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto va = space.mmu_->phys_to_virt(space, physical_address).value_or(0);

			if (!va)
				THREAD_LOG_WARN("MmGetVirtualForPhysical: 0x{:X} is not mapped anywhere",
					physical_address);
			else
				THREAD_LOG_INFO("MmGetVirtualForPhysical(0x{:X}) -> 0x{:X}", physical_address, va);

			return va;
		});

	state.redirect(mod, "MmCopyMemory",
		[](vcpu& cpu, const addr_t target_address, const std::uint64_t source_address,
			const std::uint64_t number_of_bytes, const std::uint32_t flags,
			emu_object<std::uint64_t> number_of_bytes_transferred) -> NTSTATUS
		{
			const auto kind = flags & (mm_copy_memory_physical | mm_copy_memory_virtual);

			if (kind != mm_copy_memory_physical && kind != mm_copy_memory_virtual)
			{
				THREAD_LOG_WARN("MmCopyMemory: flags 0x{:X} name neither a virtual source nor a "
					"physical one", flags);
				return STATUS_INVALID_PARAMETER;
			}

			auto& space = *cpu.curr_addr_space();
			std::vector<std::uint8_t> buffer(number_of_bytes);

			try
			{
				if (kind == mm_copy_memory_physical)
					space.mmu_->read_phys(source_address, buffer.data(), number_of_bytes);
				else
					space.read_mem(source_address, buffer.data(), number_of_bytes);
			}
			catch (const std::exception& e)
			{
				THREAD_LOG_WARN("MmCopyMemory: cannot read {} bytes from {} 0x{:X}: {}",
					number_of_bytes, kind == mm_copy_memory_physical ? "physical" : "virtual",
					source_address, e.what());

				if (number_of_bytes_transferred)
					number_of_bytes_transferred.write(0);

				return STATUS_INVALID_ADDRESS;
			}

			space.write_mem(target_address, buffer.data(), number_of_bytes);

			if (number_of_bytes_transferred)
				number_of_bytes_transferred.write(number_of_bytes);

			THREAD_LOG_INFO("MmCopyMemory(target=0x{:X}, source=0x{:X}, {} bytes, flags=0x{:X})",
				target_address, source_address, number_of_bytes, flags);

			return STATUS_SUCCESS;
		});

	// A fresh kernel window is pointed at the physical pages named; unbacked memory has none.
	auto map_io_space = [](vcpu& cpu, const std::uint64_t physical_address,
		const std::uint64_t number_of_bytes, const std::string_view who) -> addr_t
	{
		auto& space = *cpu.curr_addr_space();

		const auto base = mdl_page_base(physical_address);
		const auto offset = mdl_page_offset(physical_address);

		addr_t va = 0;

		try
		{
			va = space.map_phys(base, number_of_bytes + offset, prot_rw | prot_supervisor);
		}
		catch (const std::exception& e)
		{
			THREAD_LOG_WARN("{}: cannot map {} bytes at physical 0x{:X}: {}",
				who, number_of_bytes, physical_address, e.what());
			return 0;
		}

		THREAD_LOG_INFO("{}(physical=0x{:X}, {} bytes) -> 0x{:X}",
			who, physical_address, number_of_bytes, va + offset);

		return va + offset;
	};

	state.redirect(mod, "MmMapIoSpace",
		[map_io_space](vcpu& cpu, const std::uint64_t physical_address,
			const std::uint64_t number_of_bytes, const std::uint32_t cache_type) -> addr_t
		{
			THREAD_LOG_INFO("MmMapIoSpace: cache type {}", caching_type_name(cache_type));
			return map_io_space(cpu, physical_address, number_of_bytes, "MmMapIoSpace");
		});

	// Everything mapped here is readable and writable, so the protection only reaches the log.
	state.redirect(mod, "MmMapIoSpaceEx",
		[map_io_space](vcpu& cpu, const std::uint64_t physical_address,
			const std::uint64_t number_of_bytes, const std::uint32_t protect) -> addr_t
		{
			THREAD_LOG_INFO("MmMapIoSpaceEx: protect=0x{:X}", protect);
			return map_io_space(cpu, physical_address, number_of_bytes, "MmMapIoSpaceEx");
		});

	state.redirect(mod, "MmUnmapIoSpace",
		[](vcpu& cpu, const addr_t base_address, const std::uint64_t number_of_bytes)
		{
			auto& space = *cpu.curr_addr_space();

			THREAD_LOG_INFO("MmUnmapIoSpace(0x{:X}, {} bytes)", base_address, number_of_bytes);

			space.mmu_->unmap_virt(space, mdl_page_base(base_address),
				number_of_bytes + mdl_page_offset(base_address));
		});

	// The pool hands out one run per allocation, so a pool block already is contiguous.
	auto allocate_contiguous = [st](vcpu& cpu, const std::uint64_t number_of_bytes,
		const std::uint64_t highest_acceptable_address, const std::string_view who) -> addr_t
	{
		const auto addr = st->pool.allocate(number_of_bytes, pool_tag("MmCo"), true);

		if (!addr)
		{
			THREAD_LOG_ERR("{}: out of pool for {} bytes", who, number_of_bytes);
			return 0;
		}

		auto& space = *cpu.curr_addr_space();
		const auto pa = space.mmu_->virt_to_phys(space, addr).value_or(0);

		if (pa > highest_acceptable_address)
		{
			THREAD_LOG_WARN("{}: physical 0x{:X} is above the limit of 0x{:X} the caller gave",
				who, pa, highest_acceptable_address);

			st->pool.free(addr);
			return 0;
		}

		THREAD_LOG_INFO("{}({} bytes, highest=0x{:X}) -> 0x{:X} (physical 0x{:X})",
			who, number_of_bytes, highest_acceptable_address, addr, pa);

		return addr;
	};

	state.redirect(mod, "MmAllocateContiguousMemorySpecifyCache",
		[allocate_contiguous](vcpu& cpu, const std::uint64_t number_of_bytes,
			const std::uint64_t lowest_acceptable_address,
			const std::uint64_t highest_acceptable_address,
			const std::uint64_t boundary_address_multiple,
			const std::uint32_t cache_type) -> addr_t
		{
			THREAD_LOG_INFO("MmAllocateContiguousMemorySpecifyCache: lowest=0x{:X}, "
				"boundary=0x{:X}, cache type {}",
				lowest_acceptable_address, boundary_address_multiple, caching_type_name(cache_type));

			return allocate_contiguous(cpu, number_of_bytes, highest_acceptable_address,
				"MmAllocateContiguousMemorySpecifyCache");
		});

	state.redirect(mod, "MmAllocateContiguousNodeMemory",
		[allocate_contiguous](vcpu& cpu, const std::uint64_t number_of_bytes,
			const std::uint64_t lowest_acceptable_address,
			const std::uint64_t highest_acceptable_address,
			const std::uint64_t boundary_address_multiple,
			const std::uint32_t protect, const std::uint32_t preferred_node) -> addr_t
		{
			THREAD_LOG_INFO("MmAllocateContiguousNodeMemory: lowest=0x{:X}, boundary=0x{:X}, "
				"protect=0x{:X}, node={}",
				lowest_acceptable_address, boundary_address_multiple, protect, preferred_node);

			return allocate_contiguous(cpu, number_of_bytes, highest_acceptable_address,
				"MmAllocateContiguousNodeMemory");
		});

	state.redirect(mod, "MmFreeContiguousMemory", [st](vcpu&, const addr_t base_address)
	{
		const auto freed = st->pool.free(base_address);

		if (!freed)
		{
			THREAD_LOG_ERR("MmFreeContiguousMemory: 0x{:X} was not allocated here", base_address);
			return;
		}

		THREAD_LOG_INFO("MmFreeContiguousMemory(0x{:X}): {} bytes", base_address, freed->size);
	});

	state.redirect(mod, "MmBuildMdlForNonPagedPool",
		[](vcpu& cpu, emu_object<mdl_t> memory_descriptor_list)
		{
			if (!memory_descriptor_list)
				return;

			auto mdl = memory_descriptor_list.read();

			mdl.mapped_system_va = mdl.start_va + mdl.byte_offset;
			mdl.mdl_flags = static_cast<std::int16_t>(mdl.mdl_flags
				| mdl_mapped_to_system_va | mdl_pages_locked | mdl_source_is_nonpaged_pool);

			memory_descriptor_list.write(mdl);

			auto& space = *cpu.curr_addr_space();
			const auto first = mdl_page_base(mdl.start_va);
			const auto pages = mdl_page_count(mdl.start_va, mdl.byte_count);

			for (std::size_t i = 0; i < pages; ++i)
			{
				const auto pa = space.mmu_->virt_to_phys(space, first + i * mdl_page_size).value_or(0);

				space.write_mem<addr_t>(
					memory_descriptor_list.address() + sizeof(mdl_t) + i * sizeof(addr_t),
					pa / mdl_page_size);
			}

			THREAD_LOG_INFO("MmBuildMdlForNonPagedPool(0x{:X}): {} bytes over {} page(s) at 0x{:X}",
				memory_descriptor_list.address(), mdl.byte_count, pages, mdl.mapped_system_va);
		});

	// The physical memory handed out is one run: the mmu allocates by bumping a cursor.
	state.redirect(mod, "MmGetPhysicalMemoryRanges", [st](vcpu& cpu) -> addr_t
	{
		const auto range = cpu.curr_addr_space()->mmu_->phys_range();

		const _PHYSICAL_MEMORY_RANGE entries[2] = {
			{ .BaseAddress = { .QuadPart = static_cast<long long>(range.first) },
			  .NumberOfBytes = { .QuadPart = static_cast<long long>(range.second) } },
			{},
		};

		const auto addr = st->pool.allocate(sizeof(entries), pool_tag("MmPh"), true);

		if (!addr)
		{
			THREAD_LOG_ERR("MmGetPhysicalMemoryRanges: out of pool");
			return 0;
		}

		cpu.curr_addr_space()->write_mem(addr, entries, sizeof(entries));

		THREAD_LOG_INFO("MmGetPhysicalMemoryRanges() -> 0x{:X}: 0x{:X}..0x{:X}",
			addr, range.first, range.first + range.second);

		return addr;
	});

	// A section with no file would be pagefile backed, so it is sized by MaximumSize and zeroed.
	state.redirect(mod, "MmCreateSection",
		[st](vcpu& cpu, emu_object<addr_t> section_object, const std::uint32_t desired_access,
			[[maybe_unused]] const addr_t object_attributes,
			emu_object<std::int64_t> maximum_size,
			const std::uint32_t section_page_protection, const std::uint32_t allocation_attributes,
			const std::uint64_t file_handle, const addr_t file_object) -> NTSTATUS
		{
			if (!section_object)
				return STATUS_INVALID_PARAMETER;

			const auto max_size = maximum_size ? maximum_size.read() : 0;

			auto host = std::make_shared<section_host>();
			host->is_image = (allocation_attributes & sec_image) != 0;

			if (file_handle)
			{
				const auto file = st->sys_proc->handle_table().get_object<file_host>(file_handle);

				if (!file)
				{
					THREAD_LOG_WARN("MmCreateSection: handle 0x{:X} is not an open file",
						file_handle);
					return STATUS_INVALID_HANDLE;
				}

				host->file = file->file;
				host->path = file->path;
			}

			if (host->file && host->file->size() == 0)
			{
				THREAD_LOG_WARN("MmCreateSection: '{}' is empty", host->path);
				return STATUS_MAPPED_FILE_SIZE_ZERO;
			}

			if (!host->file && max_size <= 0)
			{
				THREAD_LOG_WARN("MmCreateSection: no file and no size, so there is nothing to map");
				return STATUS_INVALID_PARAMETER;
			}

			// An image section is sized by SizeOfImage, not by the file: a driver that maps one
			// walks it as an image, so the sections have to sit at their virtual addresses and
			// the tail past the last one has to be there to be read.
			if (host->is_image && host->file)
				host->image = krnl::pe_virtual_image(host->file->data());

			host->size = !host->image.empty()
				? static_cast<std::uint64_t>(host->image.size())
				: host->file
					? static_cast<std::uint64_t>(host->file->size())
					: static_cast<std::uint64_t>(max_size);

			// The body carries the size at the offset a caller reads it from.
			std::array<std::uint8_t, section_body_size> body{};
			const auto size = static_cast<std::int64_t>(host->size);
			std::memcpy(body.data() + section_body_size_offset, &size, sizeof(size));

			const auto path = host->path;
			const auto is_image = host->is_image;
			const auto section_size = host->size;

			const auto addr = st->objs.create_object(0, body.data(), body.size(),
				std::move(host), prot_rw | prot_supervisor);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			section_object.write(addr);

			THREAD_LOG_INFO("MmCreateSection(access=0x{:X}, max_size={}, protection=0x{:X}, "
				"allocation=0x{:X}, file=0x{:X}/0x{:X}) -> 0x{:X} ('{}', {} bytes{})",
				desired_access, max_size, section_page_protection, allocation_attributes,
				file_handle, file_object, addr, path, section_size,
				is_image ? ", image" : "");

			return STATUS_SUCCESS;
		});

	// The view is a copy of the file rather than a mapping, so a write does not reach the file.
	state.redirect(mod, "MmMapViewInSystemSpace",
		[st](vcpu& cpu, const addr_t section, emu_object<addr_t> mapped_base,
			emu_object<std::uint64_t> view_size) -> NTSTATUS
		{
			const auto host = st->objs.get_object<section_host>(section);

			if (!host)
			{
				THREAD_LOG_WARN("MmMapViewInSystemSpace: 0x{:X} is not a section", section);
				return STATUS_INVALID_PARAMETER;
			}

			auto size = view_size ? view_size.read() : 0;

			if (!size)
				size = host->size;

			if (!size)
				return STATUS_INVALID_PARAMETER;

			auto& space = *cpu.curr_addr_space();
			const auto base = space.alloc(size, prot_rw | prot_supervisor);

			if (!base)
				return STATUS_INSUFFICIENT_RESOURCES;

			const auto source = !host->image.empty()
				? std::span<const std::uint8_t>(host->image)
				: host->file ? host->file->data() : std::span<const std::uint8_t>{};

			if (!source.empty())
			{
				const auto copied = std::min<std::size_t>(size, source.size());
				space.write_mem(base, source.data(), copied);
			}

			if (mapped_base)
				mapped_base.write(base);

			if (view_size)
				view_size.write(size);

			st->views[base] = size;

			THREAD_LOG_INFO("MmMapViewInSystemSpace(section=0x{:X}, '{}') -> 0x{:X}, {} bytes",
				section, host->path, base, size);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "MmUnmapViewInSystemSpace",
		[st](vcpu& cpu, const addr_t mapped_base) -> NTSTATUS
		{
			const auto it = st->views.find(mapped_base);

			if (it == st->views.end())
			{
				THREAD_LOG_WARN("MmUnmapViewInSystemSpace: 0x{:X} is not a mapped view",
					mapped_base);
				return STATUS_INVALID_PARAMETER;
			}

			auto& space = *cpu.curr_addr_space();
			space.mmu_->unmap_virt(space, mapped_base, it->second);

			THREAD_LOG_INFO("MmUnmapViewInSystemSpace(0x{:X}): {} bytes", mapped_base, it->second);

			st->views.erase(it);

			return STATUS_SUCCESS;
		});
}
