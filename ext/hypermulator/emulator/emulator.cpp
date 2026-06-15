#include "emulator.hpp"
#include "../guest/guest_virtual_processor.hpp"
#include "../guest/guest_vmexit.hpp"
#include "../arch/decoder.hpp"

#include <ia32-doc/ia32.hpp>
#include <spdlog/spdlog.h>

template <class T, class Y>
static T align_up(T value, Y alignment)
{
	const Y remainder = value % alignment;
	const Y additional = remainder ? (alignment - remainder) : 0;

	return value + additional;
}

template <class T, class Y>
static T align_down(T value, Y alignment)
{
	return value & ~(alignment - 1);
}

bool hm::hook_t::in_range(const address_type address) const
{
	return start_address <= address && (!end_address || address < end_address);
}

bool hm::hook_t::in_aligned_range(const address_type address, const address_type size) const
{
	const address_type aligned_start = align_down(start_address, emulator_t::page_size);
	const address_type aligned_end = align_up(end_address, emulator_t::page_size);

	return aligned_start <= address + size && (!end_address || address - size < aligned_end);
}

hm::emulator_t::emulator_t(const machine_mode_t mode)
		:	partition_(std::make_shared<guest_partition_t>(1)),
			mode_(mode)
{
	if (!partition_->configure())
	{
		throw std::runtime_error("unable to configure partition");
	}

	configure_msr_properties();

	if (!partition_->finalize())
	{
		throw std::runtime_error("unable to finalize partition");
	}

	if (!load_cpu_mode_default_state())
	{
		throw std::runtime_error("unable to load CPU mode default state");
	}

	reset_guest_exit_state();
}

bool hm::emulator_t::run_at(const address_type start_address, const address_type end_address)
{
	if (mode_ == machine_mode_64 && read_register<reg::cr3, std::uint64_t>() == 0 && !create_default_page_tables())
	{
		return false;
	}

	if ((mode_ == machine_mode_32 || mode_ == machine_mode_64) &&
		read_register<reg::gdtr, guest_table_register_t>().base == 0 && !create_default_gdt())
	{
		return false;
	}

	auto processor = virtual_processor();

	set_program_counter(start_address);

	processor.run();

	if (!single_step_callbacks_.empty())
	{
		single_step_callbacks_.clear();

		for (std::size_t i = 0; i < hooks_.size(); i++)
		{
			const auto& hook = hooks_[i];

			if (hook->type != hook_type_t::memory_access)
			{
				continue;
			}

			const auto& hook_memory = std::get<hook_memory_t>(hook->extra_data);
			const address_type start_page = align_down(hook->start_address, page_size);
			const address_type end_page = align_up(hook->end_address, page_size);

			for (address_type page = start_page; page < end_page; page += page_size)
			{
				const auto protection = partition_->query_physical_memory_protection(page);

				if (protection && (*protection & hook_memory.protection))
				{
					partition_->protect_physical_memory(page, page_size, *protection & ~hook_memory.protection);
				}
			}
		}
	}

	if (end_address && program_counter() != end_address)
	{
		return false;
	}

	return true;
}

void hm::emulator_t::stop()
{
	auto processor = virtual_processor();

	processor.stop();
}

bool hm::emulator_t::configure_single_step()
{
	return partition_->set_debug_exception_exiting(true);
}

void hm::emulator_t::configure_msr_properties()
{
	partition_->set_msr_access_exiting(true);

	WHV_PARTITION_PROPERTY property = {};
	property.X64MsrExitBitmap.UnhandledMsrs = true;
	property.X64MsrExitBitmap.TscMsrWrite = true;
	property.X64MsrExitBitmap.TscMsrRead = true;
	property.X64MsrExitBitmap.ApicBaseMsrWrite = true;
	property.X64MsrExitBitmap.MiscEnableMsrRead = true;
	property.X64MsrExitBitmap.McUpdatePatchLevelMsrRead = true;

	if (!partition_->set_msr_bitmap(property))
		__debugbreak();

	if (!msr_exit_entries_.empty())
	{
		partition_->set_msr_action_list(msr_exit_entries_);
	}

	partition_->set_unimplemented_msr_action(WHvMsrActionExit);
}

void hm::emulator_t::reset_guest_exit_state()
{
	partition_->register_vmexit_callback(vmexit_reason_t::exception,
		[this](guest_virtual_processor_t& processor, vmexit_context_t& context)
		{
			return this->handle_exception(processor, context);
		}
	);

	partition_->register_vmexit_callback(vmexit_reason_t::cpuid,
		[this](guest_virtual_processor_t& processor, vmexit_context_t& context)
		{
			return this->handle_cpuid_instruction(processor, context);
		}
	);

	partition_->register_vmexit_callback(vmexit_reason_t::rdtsc,
		[this](guest_virtual_processor_t& processor, vmexit_context_t& context)
		{
			return this->handle_rdtsc_instruction(processor, context);
		}
	);

	partition_->register_vmexit_callback(vmexit_reason_t::memory_access,
		[this](guest_virtual_processor_t& processor, vmexit_context_t& context)
		{
			return this->handle_memory_access(processor, context);
		}
	);

	partition_->register_vmexit_callback(vmexit_reason_t::io_port_access,
		[this](guest_virtual_processor_t& processor, vmexit_context_t& context)
		{
			context.advance_rip(processor);

			return true;
		}
	);

	partition_->register_vmexit_callback(vmexit_reason_t::msr_access,
		[this](guest_virtual_processor_t& processor, vmexit_context_t& context)
		{
			return this->handle_msr_access(processor, context);
		}
	);

	partition_->set_cpuid_exiting(false);
	partition_->set_rdtsc_exiting(false);

	partition_->set_debug_exception_exiting(false);
	partition_->set_page_fault_exception_exiting(true);
}

bool hm::emulator_t::monitor_msr(const std::uint32_t msr_index)
{
	for (const auto& entry : msr_exit_entries_)
	{
		if (entry.Index == msr_index)
		{
			return true;
		}
	}

	WHV_MSR_ACTION_ENTRY entry = {};
	entry.Index = msr_index;
	entry.ReadAction = WHvMsrActionExit;
	entry.WriteAction = WHvMsrActionExit;

	msr_exit_entries_.push_back(entry);

	return partition_->set_msr_action_list(msr_exit_entries_);
}

bool hm::emulator_t::map_physical_memory(const address_type physical_address, const size_type size,
                                         const protection_type protection)
{
	return partition_->map_physical_memory(physical_address, size, protection);
}

bool hm::emulator_t::unmap_physical_memory(const address_type physical_address, const size_type size)
{
	return partition_->unmap_physical_memory(physical_address, size);
}

bool hm::emulator_t::protect_physical_memory(const address_type physical_address, const size_type size,
                                             const protection_type protection)
{
	return partition_->protect_physical_memory(physical_address, size, protection);
}

bool hm::emulator_t::write_physical_memory(const address_type physical_address, const void* const buffer,
                                           const size_type size)
{
	return partition_->write_physical_memory(physical_address, buffer, size);
}

bool hm::emulator_t::write_physical_memory(const address_type physical_address,
                                           const std::span<const std::uint8_t> buffer)
{
	return write_physical_memory(physical_address, buffer.data(), buffer.size());
}

bool hm::emulator_t::read_physical_memory(const address_type physical_address, void* const buffer,
                                          const size_type size) const
{
	return partition_->read_physical_memory(physical_address, buffer, size);
}

bool hm::emulator_t::read_physical_memory(const address_type physical_address,
                                          const std::span<std::uint8_t> buffer) const
{
	return read_physical_memory(physical_address, buffer.data(), buffer.size());
}

std::optional<hm::emulator_t::address_type> hm::emulator_t::translate_virtual_address(const address_type address) const
{
	const auto processor = virtual_processor();

	return processor.translate_virtual_address(address);
}

bool hm::emulator_t::write_register(const guest_register_t& guest_register, const void* const value,
                                    const size_type size)
{
	auto processor = virtual_processor();

	return processor.write_register(guest_register, value, size);
}

bool hm::emulator_t::read_register(const guest_register_t& guest_register, void* const value,
                                   const size_type size) const
{
	const auto processor = virtual_processor();

	return processor.read_register(guest_register, value, size);
}

hm::emulator_t::address_type hm::emulator_t::program_counter() const
{
	return read_register<reg::rip, address_type>();
}

void hm::emulator_t::set_program_counter(const address_type program_counter)
{
	return write_register<reg::rip>(program_counter);
}

hm::guest_virtual_processor_t hm::emulator_t::virtual_processor() const
{
	const auto virtual_processors = partition_->virtual_processors();

	if (virtual_processors.empty())
	{
		throw std::logic_error("partition has no virtual processors");
	}

	return virtual_processors[0];
}
