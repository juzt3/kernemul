#include "guest_partition.hpp"
#include "guest_virtual_processor.hpp"
#include "guest_register.hpp"

#include <spdlog/spdlog.h>
#include <algorithm>
#include <ranges>
#include <cstring>

static void* aligned_mem_alloc(const std::size_t size)
{
	void* const buf = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	return buf;
}

static void mem_free(void* const buf)
{
	VirtualFree(buf, 0, MEM_RELEASE);
}

static bool is_page_aligned(const std::size_t value)
{
	return (value % hm::partition::page_size) == 0;
}

template <class T, class Y>
static T align_down(T value, Y alignment)
{
	return value & ~(alignment - 1);
}

hm::partition::partition(const std::size_t cpu_count)
		:	cpus_(cpu_count)
{
	if (!cpu_count)
	{
		throw std::logic_error("partition must have at least 1 logical processor");
	}

	if (!create_partition())
	{
		throw std::runtime_error("unable to create partition");
	}
}

hm::partition::~partition()
{
	delete_partition();
}

bool hm::partition::set_up()
{
	const std::size_t cpu_count = cpus_.size();

	if (!set_cpu_count(cpu_count))
	{
		return false;
	}

	if (FAILED(WHvSetupPartition(handle_)))
	{
		return false;
	}

	return create_vcpus();
}

WHV_PARTITION_HANDLE hm::partition::handle() const
{
	return handle_;
}

std::span<hm::vcpu> hm::partition::cpus()
{
	return cpus_;
}

std::span<const hm::vcpu> hm::partition::cpus() const
{
	return cpus_;
}

bool hm::partition::run_vcpu(vcpu& cpu,
                                                  vmexit_context& context)
{
	WHV_RUN_VP_EXIT_CONTEXT whv_exit_context = { };

	if (FAILED(WHvRunVirtualProcessor(handle_, cpu.id(), &whv_exit_context, sizeof(whv_exit_context))))
	{
		return false;
	}

	context = vmexit_context{ whv_exit_context };

	return true;
}

bool hm::partition::stop_vcpu(vcpu& cpu)
{
	return SUCCEEDED(WHvCancelRunVirtualProcessor(handle_, cpu.id(), 0));
}

bool hm::partition::map_phys_mem(const addr_t phys_addr, const std::size_t size,
                                                const mem_prot prot)
{
	if (!is_page_aligned(phys_addr) || !is_page_aligned(size))
	{
		return false;
	}

	for (std::size_t i = 0; i < size; i += page_size)
	{
		const addr_t page_phys_addr = phys_addr + i;

		if (phys_page_mappings_.contains(page_phys_addr))
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
			page_phys_addr, page_size,
			static_cast<WHV_MAP_GPA_RANGE_FLAGS>(prot))))
		{
			return false;
		}

		phys_page_mappings_[page_phys_addr] = mapped_mem {
			.host_buf = page_buffer,
			.prot = static_cast<mem_prot>(prot)
		};
	}

	return true;
}

bool hm::partition::unmap_phys_mem(const addr_t phys_addr, const std::size_t size)
{
	if (!is_page_aligned(phys_addr) || !is_page_aligned(size))
	{
		return false;
	}

	for (std::size_t i = 0; i < size; i += page_size)
	{
		const addr_t page_phys_addr = phys_addr + i;

		const auto it = phys_page_mappings_.find(page_phys_addr);

		if (it == phys_page_mappings_.end())
		{
			return false;
		}

		if (FAILED(WHvUnmapGpaRange(handle_, page_phys_addr, page_size)))
		{
			return false;
		}

		const mapped_mem& mapping = it->second;

		mem_free(mapping.host_buf);

		phys_page_mappings_.erase(it);
	}

	return true;
}

bool hm::partition::is_phys_addr_valid(const addr_t phys_addr) const
{
	const addr_t aligned_address = align_down(phys_addr, page_size);

	return phys_page_mappings_.contains(aligned_address);
}

bool hm::partition::prot_phys_mem(const addr_t phys_addr, const std::size_t size,
                                                    const mem_prot prot)
{
	if (!is_page_aligned(phys_addr) || !is_page_aligned(size))
	{
		return false;
	}

	for (std::size_t i = 0; i < size; i += page_size)
	{
		const addr_t page_phys_addr = phys_addr + i;

		const auto it = phys_page_mappings_.find(page_phys_addr);

		if (it == phys_page_mappings_.end())
		{
			return false;
		}

		if (FAILED(WHvUnmapGpaRange(handle_, page_phys_addr, page_size)))
		{
			return false;
		}

		mapped_mem& mapping = it->second;

		if (FAILED(WHvMapGpaRange(
			handle_, mapping.host_buf,
			page_phys_addr, page_size,
			static_cast<WHV_MAP_GPA_RANGE_FLAGS>(prot))) &&
			prot & prot_read)
		{
			return false;
		}

		mapping.prot = static_cast<mem_prot>(prot);
	}

	return true;
}

std::optional<hm::mem_prot> hm::partition::query_phys_mem_prot(
	const addr_t phys_addr) const
{
	if (!is_page_aligned(phys_addr))
	{
		return { };
	}

	const auto it = phys_page_mappings_.find(phys_addr);

	if (it == phys_page_mappings_.end())
	{
		return { };
	}

	const mapped_mem& mapping = it->second;

	return mapping.prot;
}

bool hm::partition::write_phys_mem(const addr_t phys_addr, const void* const buf,
                                                  const std::size_t size)
{
	return copy_phys_mem(phys_addr, const_cast<void*>(buf), size, mem_copy_dir::write);
}

bool hm::partition::write_phys_mem(const addr_t phys_addr,
                                                  const std::span<const std::uint8_t> buf) 
{
	return write_phys_mem(phys_addr, buf.data(), buf.size());
}

bool hm::partition::read_phys_mem(const addr_t phys_addr, void* const buf,
                                                 const std::size_t size) const
{
	return copy_phys_mem(phys_addr, buf, size, mem_copy_dir::read);
}

bool hm::partition::read_phys_mem(const addr_t phys_addr,
                                                 const std::span<std::uint8_t> buf) const
{
	return read_phys_mem(phys_addr, buf.data(), buf.size());
}

bool hm::partition::copy_phys_mem(const addr_t phys_addr, void* const buf,
                                                 const std::size_t size, const mem_copy_dir direction) const
{
	std::size_t count = 0;

	while (count < size)
	{
		const addr_t current_addr = phys_addr + count;

		const auto current_mapping = find_phys_mapping(current_addr);

		if (!current_mapping)
		{
			return false;
		}

		const std::size_t page_offset = current_addr % page_size;

		const std::size_t size_remain = size - count;
		const std::size_t page_remain = page_size - page_offset;

		if (!page_remain)
		{
			return false;
		}

		const std::size_t current_size = std::min(page_remain, size_remain);

		std::uint8_t* source = static_cast<std::uint8_t*>(buf) + count;
		std::uint8_t* destination = static_cast<std::uint8_t*>(current_mapping->host_buf) + page_offset;

		if (direction == mem_copy_dir::read)
		{
			std::swap(source, destination);
		}

		std::memcpy(destination, source, current_size);

		count += current_size;
	}

	return count == size;
}

bool hm::partition::copy_virt_mem(const vcpu& cpu,
                                                const addr_t virt_addr, void* const buf,
                                                const std::size_t size,
                                                const mem_copy_dir direction) const
{
	std::size_t count = 0;

	while (count < size)
	{
		const addr_t current_virt_addr = virt_addr + count;

		const auto current_phys_addr = virt_to_phys(cpu, current_virt_addr);

		if (!current_phys_addr)
		{
			return false;
		}

		const std::size_t page_offset = current_virt_addr % page_size;

		const std::size_t size_remain = size - count;
		const std::size_t page_remain = page_size - page_offset;

		if (!page_remain)
		{
			return false;
		}

		const std::size_t current_size = std::min(page_remain, size_remain);

		if (!copy_phys_mem(*current_phys_addr, buf, current_size, direction))
		{
			return false;
		}

		count += current_size;
	}

	return count == size;
}

std::optional<hm::addr_t> hm::partition::virt_to_phys(
	const vcpu& cpu, const addr_t virt_addr) const
{
	WHV_TRANSLATE_GVA_RESULT result = { };
	addr_t phys_addr = 0;

	if (FAILED(WHvTranslateGva(handle_, cpu.id(), virt_addr, WHvTranslateGvaFlagValidateRead, &result, &phys_addr)) ||
		result.ResultCode != WHvTranslateGvaResultSuccess)
	{
		return { };
	}

	return phys_addr;
}

bool hm::partition::write_virt_mem(vcpu& cpu,
                                                 const addr_t virt_addr, const void* const buf,
                                                 const std::size_t size)
{
	return copy_virt_mem(cpu, virt_addr, const_cast<void*>(buf), size, mem_copy_dir::write);
}

bool hm::partition::write_virt_mem(vcpu& cpu,
                                                 const addr_t virt_addr,
                                                 const std::span<const std::uint8_t> buf)
{
	return write_virt_mem(cpu, virt_addr, buf.data(), buf.size());
}

bool hm::partition::read_virt_mem(const vcpu& cpu,
                                                const addr_t virt_addr, void* const buf,
                                                const std::size_t size) const
{
	return copy_virt_mem(cpu, virt_addr, buf, size, mem_copy_dir::read);
}

bool hm::partition::read_virt_mem(const vcpu& cpu,
                                                const addr_t virt_addr,
                                                const std::span<std::uint8_t> buf) const
{
	return read_virt_mem(cpu, virt_addr, buf.data(), buf.size());
}

bool hm::partition::reg_write(vcpu& cpu,
                                           const reg_t& r, const void* const value,
                                           const std::size_t size)
{
	const WHV_REGISTER_NAME register_id = r.id;

	WHV_REGISTER_VALUE whv_value = { }; 

	std::memcpy(&whv_value, value, size);

	return SUCCEEDED(WHvSetVirtualProcessorRegisters(handle_, cpu.id(), &register_id, 1, &whv_value));
}

bool hm::partition::reg_read(const vcpu& cpu,
                                          const reg_t& r, void* value,
                                          const std::size_t size) const
{
	const WHV_REGISTER_NAME register_id = r.id;

	WHV_REGISTER_VALUE whv_value = { };

	const bool status = SUCCEEDED(
		WHvGetVirtualProcessorRegisters(handle_, cpu.id(), &register_id, 1, &whv_value));

	std::memcpy(value, &whv_value, size);

	return status;
}

#define ENABLE_CALLBACK_EXITING(name)\
	if (reason == vmexit_reason::name && !set_##name##_exiting(true))\
	{\
		return false;\
	}

bool hm::partition::register_vmexit_cb(const vmexit_reason reason,
                                                     const vmexit_callback::routine_t& cb)
{
	// unsupported
	if (reason == vmexit_reason::apic_write_trap)
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

	vmexit_cbs_.emplace_back(reason, cb);

	return true;
}

bool hm::partition::run_vmexit_cbs(vcpu& cpu,
                                                 vmexit_context& context) const
{
	bool cb_ran = false;

	const bool cb_status = std::ranges::all_of(vmexit_cbs_,
		[&](const vmexit_callback& cb) -> bool
		{
			if (cb.reason != context.reason)
			{
				return true;
			}

			cb_ran = true;

			return cb.cb(cpu, context);
		}
	);

	return cb_ran && cb_status;
}

bool hm::partition::create_partition()
{
	return SUCCEEDED(WHvCreatePartition(&handle_));
}

bool hm::partition::delete_partition()
{
	if (handle_ && SUCCEEDED(WHvDeletePartition(handle_)))
	{
		handle_ = nullptr;

		return true;
	}

	return false;
}

bool hm::partition::create_vcpus()
{
	for (std::uint32_t i = 0; i < cpus_.size(); i++)
	{
		if (FAILED(WHvCreateVirtualProcessor(handle_, i, 0)))
		{
			return false;
		}

		cpus_[i] = vcpu{ shared_from_this(), i };
	}

	return true;
}

bool hm::partition::set_partition_property(const WHV_PARTITION_PROPERTY_CODE code,
                                                   const WHV_PARTITION_PROPERTY& property) const
{
	return SUCCEEDED(WHvSetPartitionProperty(handle_, code, &property, sizeof(property)));
}

bool hm::partition::set_cpu_count(const std::size_t count) const
{
	WHV_PARTITION_PROPERTY property;

	property.ProcessorCount = static_cast<std::uint32_t>(count);

	return set_partition_property(WHvPartitionPropertyCodeProcessorCount, property);
}

bool hm::partition::set_extended_vmexits(const WHV_EXTENDED_VM_EXITS extended_vmexits) const
{
	WHV_PARTITION_PROPERTY property;

	property.ExtendedVmExits = extended_vmexits;

	return set_partition_property(WHvPartitionPropertyCodeExtendedVmExits, property);
}

bool hm::partition::set_exception_exit_bitmap(const std::uint64_t exception_bitmap) const
{
	WHV_PARTITION_PROPERTY property;

	property.ExceptionExitBitmap = exception_bitmap;

	return set_partition_property(WHvPartitionPropertyCodeExceptionExitBitmap, property);
}

std::optional<WHV_PARTITION_PROPERTY> hm::partition::get_partition_property(
	const WHV_PARTITION_PROPERTY_CODE code) const
{
	WHV_PARTITION_PROPERTY property = { };

	if (FAILED(WHvGetPartitionProperty(handle_, code, &property, sizeof(property), nullptr)))
	{
		return { };
	}

	return property;
}

WHV_EXTENDED_VM_EXITS hm::partition::query_extended_vmexits() const
{
	const auto partition_property = get_partition_property(WHvPartitionPropertyCodeExtendedVmExits);

	if (!partition_property)
	{
		throw std::runtime_error("unable to query partition extended VMEXITs");
	}

	return partition_property->ExtendedVmExits;
}

std::uint64_t hm::partition::query_exception_exit_bitmap() const
{
	const auto partition_property = get_partition_property(WHvPartitionPropertyCodeExceptionExitBitmap);

	if (!partition_property)
	{
		throw std::runtime_error("unable to query partition exception bitmap");
	}

	return partition_property->ExceptionExitBitmap;
}

std::optional<hm::mapped_mem> hm::partition::find_phys_mapping(
	const addr_t phys_addr) const
{
	const addr_t aligned_physical_address = phys_addr - (phys_addr % page_size);

	const auto it = phys_page_mappings_.find(aligned_physical_address);

	if (it == phys_page_mappings_.end())
	{
		return { };
	}

	return it->second;
}
