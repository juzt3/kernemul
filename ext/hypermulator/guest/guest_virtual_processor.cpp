#include "guest_virtual_processor.hpp"
#include "guest_partition.hpp"
#include "guest_register.hpp"

#include <ia32-doc/ia32.hpp>
#include <spdlog/spdlog.h>

hm::guest_virtual_processor_t::id_type hm::guest_virtual_processor_t::id() const
{
	return id_;
}

void hm::guest_virtual_processor_t::run()
{
	constexpr std::uint64_t zero_8 = 0;
	constexpr std::uint8_t zero_16[16] = { };

	write_register(reg::pending_interruption, &zero_8, sizeof(zero_8));
	write_register(reg::pending_event, &zero_16, sizeof(zero_16));
	write_register(reg::interrupt_state, &zero_8, sizeof(zero_8));

	vmexit_context_t vmexit_context;

	do
	{
		if (!partition_->run_virtual_processor(*this, vmexit_context))
		{
			break;
		}

	} while (process_vmexit(vmexit_context));
}

std::optional<hm::guest_virtual_processor_t::address_type> hm::guest_virtual_processor_t::translate_virtual_address(
	const address_type virtual_address) const
{
	return partition_->translate_virtual_address(*this, virtual_address);
}

bool hm::guest_virtual_processor_t::write_virtual_memory(const address_type virtual_address, const void* const buffer,
                                                         const size_type size)
{
	return partition_->write_virtual_memory(*this, virtual_address, buffer, size);
}

bool hm::guest_virtual_processor_t::write_virtual_memory(const address_type virtual_address, const std::span<const std::uint8_t> buffer)
{
	return write_virtual_memory(virtual_address, buffer.data(), buffer.size());
}

bool hm::guest_virtual_processor_t::read_virtual_memory(const address_type virtual_address, void* const buffer,
                                                        const size_type size) const
{
	return partition_->read_virtual_memory(*this, virtual_address, buffer, size);
}

bool hm::guest_virtual_processor_t::read_virtual_memory(const address_type virtual_address,
                                                        const std::span<std::uint8_t> buffer) const
{
	return read_virtual_memory(virtual_address, buffer.data(), buffer.size());
}

bool hm::guest_virtual_processor_t::read_memory(const address_type address, void* const buffer, const size_type size) const
{
	if (!uses_paging())
	{
		return partition_->read_physical_memory(address, buffer, size);
	}

	return read_virtual_memory(address, buffer, size);
}

bool hm::guest_virtual_processor_t::read_memory(const address_type address, const std::span<std::uint8_t> buffer) const
{
	return read_memory(address, buffer.data(), buffer.size());
}

bool hm::guest_virtual_processor_t::write_memory(const address_type address, const void* const buffer,
                                                 const size_type size)
{
	if (!uses_paging())
	{
		return partition_->write_physical_memory(address, buffer, size);
	}

	return write_virtual_memory(address, buffer, size);
}

bool hm::guest_virtual_processor_t::write_memory(const address_type address,
                                                 const std::span<const std::uint8_t> buffer)
{
	return write_memory(address, buffer.data(), buffer.size());
}

bool hm::guest_virtual_processor_t::process_vmexit(vmexit_context_t& context)
{
	return partition_->run_vmexit_callbacks(*this, context);
}

bool hm::guest_virtual_processor_t::write_register(const guest_register_t& guest_register, const void* const value,
                                                   const size_type size)
{
	return partition_->write_register(*this, guest_register, value, size);
}

bool hm::guest_virtual_processor_t::read_register(const guest_register_t& guest_register, void* const value,
                                                  const size_type size) const
{
	return partition_->read_register(*this, guest_register, value, size);
}

bool hm::guest_virtual_processor_t::uses_paging() const
{
	const cr0 current_cr0 = read_register<reg::cr0, cr0>();

	return current_cr0.paging_enable;
}
