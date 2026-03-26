#include "guest_partition.hpp"
#include "guest_virtual_processor.hpp"
#include "guest_register.hpp"

#include <spdlog/spdlog.h>
#include <ranges>

static void* aligned_mem_alloc(const std::size_t size)
{
	return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static void mem_free(void* const buffer)
{
	VirtualFree(buffer, 0, MEM_RELEASE);
}

static bool is_page_aligned(const std::size_t value)
{
	return (value % hm::guest_partition_t::page_size) == 0;
}

template <class T, class Y>
static T align_down(T value, Y alignment)
{
	return value & ~(alignment - 1);
}

hm::guest_partition_t::guest_partition_t(const size_type processor_count)
		:	virtual_processors_(processor_count)
{
	if (!processor_count)
	{
		throw std::logic_error("partition must have at least 1 logical processor");
	}

	if (!create_partition())
	{
		throw std::runtime_error("unable to create partition");
	}
}

hm::guest_partition_t::~guest_partition_t()
{
	delete_partition();
}

bool hm::guest_partition_t::set_up()
{
	const size_type processor_count = virtual_processors_.size();

	if (!set_code_processor_count(processor_count))
	{
		return false;
	}

	if (FAILED(WHvSetupPartition(handle_)))
	{
		return false;
	}

	return create_virtual_processors();
}

hm::guest_partition_t::handle_type hm::guest_partition_t::handle() const
{
	return handle_;
}

std::span<hm::guest_virtual_processor_t> hm::guest_partition_t::virtual_processors()
{
	return virtual_processors_;
}

std::span<const hm::guest_virtual_processor_t> hm::guest_partition_t::virtual_processors() const
{
	return virtual_processors_;
}

bool hm::guest_partition_t::run_virtual_processor(guest_virtual_processor_t& virtual_processor,
                                                  vmexit_context_t& vmexit_context)
{
	WHV_RUN_VP_EXIT_CONTEXT whv_exit_context = { };

	if (FAILED(WHvRunVirtualProcessor(handle_, virtual_processor.id(), &whv_exit_context, sizeof(whv_exit_context))))
	{
		return false;
	}

	vmexit_context = vmexit_context_t{ whv_exit_context };

	return true;
}

bool hm::guest_partition_t::stop_virtual_processor(guest_virtual_processor_t& virtual_processor)
{
	return SUCCEEDED(WHvCancelRunVirtualProcessor(handle_, virtual_processor.id(), 0));
}

bool hm::guest_partition_t::map_physical_memory(const address_type physical_address, const size_type size,
                                                const protection_type protection)
{
	if (!is_page_aligned(physical_address) || !is_page_aligned(size))
	{
		return false;
	}

	for (size_type i = 0; i < size; i += page_size)
	{
		const address_type page_physical_address = physical_address + i;

		if (physical_page_mappings_.contains(page_physical_address))
		{
			return false;
		}

		void* const page_buffer = aligned_mem_alloc(page_size);

		if (!page_buffer)
		{
			return false;
		}

		if (FAILED(WHvMapGpaRange(
			handle_, page_buffer,
			page_physical_address, page_size,
			static_cast<WHV_MAP_GPA_RANGE_FLAGS>(protection))))
		{
			return false;
		}

		physical_page_mappings_[page_physical_address] = mapped_memory_t {
			.host_buffer = page_buffer,
			.protection = static_cast<protection_t>(protection)
		};
	}

	return true;
}

bool hm::guest_partition_t::unmap_physical_memory(const address_type physical_address, const size_type size)
{
	if (!is_page_aligned(physical_address) || !is_page_aligned(size))
	{
		return false;
	}

	for (size_type i = 0; i < size; i += page_size)
	{
		const address_type page_physical_address = physical_address + i;

		const auto it = physical_page_mappings_.find(page_physical_address);

		if (it == physical_page_mappings_.end())
		{
			return false;
		}

		if (FAILED(WHvUnmapGpaRange(handle_, page_physical_address, page_size)))
		{
			return false;
		}

		const mapped_memory_t& mapping = it->second;

		mem_free(mapping.host_buffer);

		physical_page_mappings_.erase(it);
	}

	return true;
}

bool hm::guest_partition_t::is_physical_address_valid(const address_type physical_address) const
{
	const address_type aligned_address = align_down(physical_address, page_size);

	return physical_page_mappings_.contains(aligned_address);
}

bool hm::guest_partition_t::protect_physical_memory(const address_type physical_address, const size_type size,
                                                    const protection_type protection)
{
	if (!is_page_aligned(physical_address) || !is_page_aligned(size))
	{
		return false;
	}

	for (size_type i = 0; i < size; i += page_size)
	{
		const address_type page_physical_address = physical_address + i;

		const auto it = physical_page_mappings_.find(page_physical_address);

		if (it == physical_page_mappings_.end())
		{
			return false;
		}

		if (FAILED(WHvUnmapGpaRange(handle_, page_physical_address, page_size)))
		{
			return false;
		}

		mapped_memory_t& mapping = it->second;

		if (FAILED(WHvMapGpaRange(
			handle_, mapping.host_buffer,
			page_physical_address, page_size,
			static_cast<WHV_MAP_GPA_RANGE_FLAGS>(protection))) &&
			protection & prot_read)
		{
			return false;
		}

		mapping.protection = static_cast<protection_t>(protection);
	}

	return true;
}

std::optional<hm::guest_partition_t::protection_type> hm::guest_partition_t::query_physical_memory_protection(
	const address_type physical_address) const
{
	if (!is_page_aligned(physical_address))
	{
		return { };
	}

	const auto it = physical_page_mappings_.find(physical_address);

	if (it == physical_page_mappings_.end())
	{
		return { };
	}

	const mapped_memory_t& mapping = it->second;

	return mapping.protection;
}

bool hm::guest_partition_t::write_physical_memory(const address_type physical_address, const void* const buffer,
                                                  const size_type size)
{
	return copy_physical_memory(physical_address, const_cast<void*>(buffer), size, memory_copy_direction_t::write);
}

bool hm::guest_partition_t::write_physical_memory(const address_type physical_address,
                                                  const std::span<const std::uint8_t> buffer) 
{
	return write_physical_memory(physical_address, buffer.data(), buffer.size());
}

bool hm::guest_partition_t::read_physical_memory(const address_type physical_address, void* const buffer,
                                                 const size_type size) const
{
	return copy_physical_memory(physical_address, buffer, size, memory_copy_direction_t::read);
}

bool hm::guest_partition_t::read_physical_memory(const address_type physical_address,
                                                 const std::span<std::uint8_t> buffer) const
{
	return read_physical_memory(physical_address, buffer.data(), buffer.size());
}

bool hm::guest_partition_t::copy_physical_memory(const address_type physical_address, void* const buffer,
                                                 const size_type size, const memory_copy_direction_t direction) const
{
	size_type count = 0;

	while (count < size)
	{
		const address_type current_address = physical_address + count;

		const auto current_mapping = find_physical_mapping(current_address);

		if (!current_mapping)
		{
			return false;
		}

		const size_type page_offset = current_address % page_size;

		const size_type size_remain = size - count;
		const size_type page_remain = page_size - page_offset;

		if (!page_remain)
		{
			return false;
		}

		const size_type current_size = std::min(page_remain, size_remain);

		std::uint8_t* source = static_cast<std::uint8_t*>(buffer) + count;
		std::uint8_t* destination = static_cast<std::uint8_t*>(current_mapping->host_buffer) + page_offset;

		if (direction == memory_copy_direction_t::read)
		{
			std::swap(source, destination);
		}

		std::memcpy(destination, source, current_size);

		count += current_size;
	}

	return count == size;
}

bool hm::guest_partition_t::copy_virtual_memory(const guest_virtual_processor_t& virtual_processor,
                                                const address_type virtual_address, void* const buffer,
                                                const size_type size,
                                                const memory_copy_direction_t direction) const
{
	size_type count = 0;

	while (count < size)
	{
		const address_type current_virtual_address = virtual_address + count;

		const auto current_physical_address = translate_virtual_address(virtual_processor, current_virtual_address);

		if (!current_physical_address)
		{
			return false;
		}

		const size_type page_offset = current_virtual_address % page_size;

		const size_type size_remain = size - count;
		const size_type page_remain = page_size - page_offset;

		if (!page_remain)
		{
			return false;
		}

		const size_type current_size = std::min(page_remain, size_remain);

		if (!copy_physical_memory(*current_physical_address, buffer, current_size, direction))
		{
			return false;
		}

		count += current_size;
	}

	return count == size;
}

std::optional<hm::guest_partition_t::address_type> hm::guest_partition_t::translate_virtual_address(
	const guest_virtual_processor_t& virtual_processor, const address_type virtual_address) const
{
	WHV_TRANSLATE_GVA_RESULT result = { };
	address_type physical_address = 0;

	if (FAILED(WHvTranslateGva(handle_, virtual_processor.id(), virtual_address, WHvTranslateGvaFlagValidateRead, &result, &physical_address)) ||
		result.ResultCode != WHvTranslateGvaResultSuccess)
	{
		return { };
	}

	return physical_address;
}

bool hm::guest_partition_t::write_virtual_memory(guest_virtual_processor_t& virtual_processor,
                                                 const address_type virtual_address, const void* const buffer,
                                                 const size_type size)
{
	return copy_virtual_memory(virtual_processor, virtual_address, const_cast<void*>(buffer), size, memory_copy_direction_t::write);
}

bool hm::guest_partition_t::write_virtual_memory(guest_virtual_processor_t& virtual_processor,
                                                 const address_type virtual_address,
                                                 const std::span<const std::uint8_t> buffer)
{
	return write_virtual_memory(virtual_processor, virtual_address, buffer.data(), buffer.size());
}

bool hm::guest_partition_t::read_virtual_memory(const guest_virtual_processor_t& virtual_processor,
                                                const address_type virtual_address, void* const buffer,
                                                const size_type size) const
{
	return copy_virtual_memory(virtual_processor, virtual_address, buffer, size, memory_copy_direction_t::read);
}

bool hm::guest_partition_t::read_virtual_memory(const guest_virtual_processor_t& virtual_processor,
                                                const address_type virtual_address,
                                                const std::span<std::uint8_t> buffer) const
{
	return read_virtual_memory(virtual_processor, virtual_address, buffer.data(), buffer.size());
}

bool hm::guest_partition_t::write_register(guest_virtual_processor_t& virtual_processor,
                                           const guest_register_t& guest_register, const void* const value,
                                           const size_type size)
{
	const WHV_REGISTER_NAME register_id = guest_register.id;

	WHV_REGISTER_VALUE whv_value = { }; 

	std::memcpy(&whv_value, value, size);

	return SUCCEEDED(WHvSetVirtualProcessorRegisters(handle_, virtual_processor.id(), &register_id, 1, &whv_value));
}

bool hm::guest_partition_t::read_register(const guest_virtual_processor_t& virtual_processor,
                                          const guest_register_t& guest_register, void* value,
                                          const size_type size) const
{
	const WHV_REGISTER_NAME register_id = guest_register.id;

	WHV_REGISTER_VALUE whv_value = { };

	const bool status = SUCCEEDED(
		WHvGetVirtualProcessorRegisters(handle_, virtual_processor.id(), &register_id, 1, &whv_value));

	std::memcpy(value, &whv_value, size);

	return status;
}

#define ENABLE_CALLBACK_EXITING(name)\
	if (reason == vmexit_reason_t::name && !set_##name##_exiting(true))\
	{\
		return false;\
	}

bool hm::guest_partition_t::register_vmexit_callback(const vmexit_reason_t reason,
                                                     const vmexit_callback_t::routine_type& routine)
{
	// unsupported
	if (reason == vmexit_reason_t::apic_write_trap)
	{
		return false;
	}

	ENABLE_CALLBACK_EXITING(cpuid)
	ENABLE_CALLBACK_EXITING(rdtsc)
	ENABLE_CALLBACK_EXITING(msr_access)
	ENABLE_CALLBACK_EXITING(exception)
	ENABLE_CALLBACK_EXITING(apic_smi_trap)
	ENABLE_CALLBACK_EXITING(hypercall)
	ENABLE_CALLBACK_EXITING(apic_init_sipi_trap)

	vmexit_callbacks_.emplace_back(reason, routine);

	return true;
}

bool hm::guest_partition_t::run_vmexit_callbacks(guest_virtual_processor_t& virtual_processor,
                                                 vmexit_context_t& context) const
{
	bool callback_ran = false;

	const bool callback_status = std::ranges::all_of(vmexit_callbacks_,
		[&](const vmexit_callback_t& callback) -> bool
		{
			if (callback.reason != context.reason)
			{
				return true;
			}

			callback_ran = true;

			return callback.routine(virtual_processor, context);
		}
	);

	return callback_ran && callback_status;
}

bool hm::guest_partition_t::create_partition()
{
	return SUCCEEDED(WHvCreatePartition(&handle_));
}

bool hm::guest_partition_t::delete_partition()
{
	if (handle_ && SUCCEEDED(WHvDeletePartition(handle_)))
	{
		handle_ = nullptr;

		return true;
	}

	return false;
}

bool hm::guest_partition_t::create_virtual_processors()
{
	for (guest_virtual_processor_t::id_type i = 0; i < virtual_processors_.size(); i++)
	{
		if (FAILED(WHvCreateVirtualProcessor(handle_, i, 0)))
		{
			return false;
		}

		virtual_processors_[i] = guest_virtual_processor_t{ shared_from_this(), i };
	}

	return true;
}

bool hm::guest_partition_t::set_partition_property(const WHV_PARTITION_PROPERTY_CODE code,
                                                   const WHV_PARTITION_PROPERTY& property) const
{
	return SUCCEEDED(WHvSetPartitionProperty(handle_, code, &property, sizeof(property)));
}

bool hm::guest_partition_t::set_code_processor_count(const size_type count) const
{
	WHV_PARTITION_PROPERTY property;

	property.ProcessorCount = static_cast<std::uint32_t>(count);

	return set_partition_property(WHvPartitionPropertyCodeProcessorCount, property);
}

bool hm::guest_partition_t::set_extended_vmexits(const WHV_EXTENDED_VM_EXITS extended_vmexits) const
{
	WHV_PARTITION_PROPERTY property;

	property.ExtendedVmExits = extended_vmexits;

	return set_partition_property(WHvPartitionPropertyCodeExtendedVmExits, property);
}

bool hm::guest_partition_t::set_exception_exit_bitmap(const bitmap_type exception_bitmap) const
{
	WHV_PARTITION_PROPERTY property;

	property.ExceptionExitBitmap = exception_bitmap;

	return set_partition_property(WHvPartitionPropertyCodeExceptionExitBitmap, property);
}

std::optional<WHV_PARTITION_PROPERTY> hm::guest_partition_t::get_partition_property(
	const WHV_PARTITION_PROPERTY_CODE code) const
{
	WHV_PARTITION_PROPERTY property = { };

	if (FAILED(WHvGetPartitionProperty(handle_, code, &property, sizeof(property), nullptr)))
	{
		return { };
	}

	return property;
}

WHV_EXTENDED_VM_EXITS hm::guest_partition_t::query_extended_vmexits() const
{
	const auto partition_property = get_partition_property(WHvPartitionPropertyCodeExtendedVmExits);

	if (!partition_property)
	{
		throw std::runtime_error("unable to query partition extended VMEXITs");
	}

	return partition_property->ExtendedVmExits;
}

hm::guest_partition_t::bitmap_type hm::guest_partition_t::query_exception_exit_bitmap() const
{
	const auto partition_property = get_partition_property(WHvPartitionPropertyCodeExceptionExitBitmap);

	if (!partition_property)
	{
		throw std::runtime_error("unable to query partition exception bitmap");
	}

	return partition_property->ExceptionExitBitmap;
}

std::optional<hm::mapped_memory_t> hm::guest_partition_t::find_physical_mapping(
	const address_type physical_address) const
{
	const address_type aligned_physical_address = physical_address - (physical_address % page_size);

	const auto it = physical_page_mappings_.find(aligned_physical_address);

	if (it == physical_page_mappings_.end())
	{
		return { };
	}

	return it->second;
}
