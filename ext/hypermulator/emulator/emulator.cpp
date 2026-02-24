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

static bool is_control_flow_instruction(const hm::machine_mode_t mode, const std::span<const std::uint8_t> instruction_bytes)
{
	const auto decoded_instruction = hm::decode_instruction(mode, instruction_bytes);

	if (!decoded_instruction)
	{
		return false;
	}

	return decoded_instruction->is_jump() || decoded_instruction->is_call() ||
		decoded_instruction->is_ret() || decoded_instruction->is_interrupt() ||
		decoded_instruction->is_syscall();
};

static void set_trap_flag(hm::guest_virtual_processor_t& processor, const bool state)
{
	rflags current_flags = processor.read_register<hm::reg::rflags, rflags>();

	current_flags.trap_flag = state;

	processor.write_register<hm::reg::rflags>(current_flags);
}

static void shadow_guest_interrupts(hm::guest_virtual_processor_t& processor, const bool state)
{
	auto interrupt_state = processor.read_register<hm::reg::interrupt_state, WHV_X64_INTERRUPT_STATE_REGISTER>();

	interrupt_state.InterruptShadow = state;

	processor.write_register<hm::reg::interrupt_state>(interrupt_state);
}

static void block_pending_single_step_exception(hm::guest_virtual_processor_t& processor)
{
	auto debug_exception = processor.read_register<hm::reg::pending_debug_exception, WHV_X64_PENDING_DEBUG_EXCEPTION>();

	debug_exception.SingleStep = 0;

	processor.write_register<hm::reg::pending_debug_exception>(debug_exception);
}

bool hm::hook_t::in_range(const address_type address) const
{
	return start_address <= address && (!end_address || address < end_address);
}

bool hm::hook_t::in_aligned_range(const address_type address) const
{
	const address_type aligned_start = align_down(start_address, emulator_t::page_size);
	const address_type aligned_end = align_up(end_address, emulator_t::page_size);

	return aligned_start <= address && (!end_address || address < aligned_end);
}

hm::emulator_t::emulator_t(const machine_mode_t mode)
		:	partition_(std::make_shared<guest_partition_t>(1)),
			mode_(mode)
{
	if (!partition_->set_up())
	{
		throw std::runtime_error("unable to set up partition");
	}

	if (!load_cpu_mode_default_state())
	{
		throw std::runtime_error("unable to load CPU mode default state");
	}

	partition_->register_vmexit_callback(vmexit_reason_t::exception,
	                                     [this](guest_virtual_processor_t& processor, vmexit_context_t& context)
	                                     {
		                                     return this->handle_exception(processor, context);
	                                     });

	partition_->register_vmexit_callback(vmexit_reason_t::cpuid,
	                                     [this](guest_virtual_processor_t& processor, vmexit_context_t& context)
	                                     {
		                                     return this->handle_cpuid_instruction(processor, context);
	                                     });

	partition_->register_vmexit_callback(vmexit_reason_t::rdtsc,
	                                     [this](guest_virtual_processor_t& processor, vmexit_context_t& context)
	                                     {
		                                     return this->handle_rdtsc_instruction(processor, context);
	                                     });

	partition_->register_vmexit_callback(vmexit_reason_t::memory_access,
	                                     [this](guest_virtual_processor_t& processor, vmexit_context_t& context)
	                                     {
		                                     return this->handle_memory_access(processor, context);
	                                     });

	partition_->set_cpuid_exiting(false);
	partition_->set_rdtsc_exiting(false);
	partition_->set_debug_exception_exiting(false);
}

bool hm::emulator_t::run_at(const address_type start_address, const address_type end_address)
{
	if (mode_ == machine_mode_64 && read_register<reg::cr3, std::uint64_t>() == 0 && !create_default_page_tables())
	{
		return false;
	}

	auto processor = virtual_processor();

	set_program_counter(start_address);

	processor.run();

	if (end_address && program_counter() != end_address)
	{
		return false;
	}

	return true;
}

bool hm::emulator_t::configure_single_step()
{
	return partition_->set_debug_exception_exiting(true);
}

void hm::emulator_t::single_step(guest_virtual_processor_t& processor, vmexit_context_t& context)
{
	for (std::uint32_t i = 0; i < single_step_callbacks_.size(); i++)
	{
		const auto it = single_step_callbacks_.begin() + i;

		if ((*it)(processor, context) == false)
		{
			single_step_callbacks_.erase(it);

			i--;
		}
	}

	// todo: find a way to check if the trap flag was set by the emulator
	if (context.reason == vmexit_reason_t::exception &&
		context.exception.id == exception_id_t::debug_trap)
	{
		set_trap_flag(processor, !single_step_callbacks_.empty());
	}
}

std::shared_ptr<hm::hook_t> hm::emulator_t::hook_code(const hook_t::code_callback& callback, const address_type start_address,
                                                      const address_type end_address)
{
	if (!configure_single_step())
	{
		return { };
	}

	const address_type aligned_start = align_down(start_address, page_size);
	const address_type aligned_end = align_up(end_address, page_size);

	const size_type aligned_size = aligned_end - aligned_start;

	// todo: go page by page on the protections
	if (!partition_->protect_physical_memory(aligned_start, aligned_size, prot_read_write))
	{
		return { };
	}

	return add_hook(callback, hook_type_t::code, start_address, end_address);
}

std::shared_ptr<hm::hook_t> hm::emulator_t::hook_basic_block(const hook_t::code_callback& callback,
                                                             const address_type start_address,
                                                             const address_type end_address)
{
	if (!configure_single_step())
	{
		return { };
	}

	const address_type aligned_start = align_down(start_address, page_size);
	const address_type aligned_end = align_up(end_address, page_size);

	const size_type aligned_size = aligned_end - aligned_start;

	// todo: go page by page on the protections
	if (!partition_->protect_physical_memory(aligned_start, aligned_size, prot_read_write))
	{
		return { };
	}

	constexpr hook_basic_block_t extra_data = {
		.was_control_flow = false
	};

	return add_hook(callback, hook_type_t::basic_block, start_address, end_address, extra_data);
}

bool hm::emulator_t::handle_exception(guest_virtual_processor_t& processor, vmexit_context_t& context)
{
	const exception_vmexit_t info = context.exception;

	if (info.id == exception_id_t::debug_trap)
	{
		single_step(processor, context);
	}

	return true;
}

bool hm::emulator_t::handle_memory_access(guest_virtual_processor_t& processor, vmexit_context_t& context)
{
	bool handled = false;
	bool step_handled = false;

	for (const auto& hook : hooks_)
	{
		switch (hook->type)
		{
		case hook_type_t::code:
		case hook_type_t::basic_block:
			handled |= memory_process_block_code_hook(processor, context, hook);
			break;
		case hook_type_t::memory_access:
		case hook_type_t::invalid_memory:
			handled |= memory_process_memory_hook(processor, context, hook, step_handled);
			break;
		default:
			break;
		}
	}

	return handled;
}

void hm::emulator_t::set_block_code_hook_step(const std::shared_ptr<hook_t>& hook)
{
	single_step_callbacks_.emplace_back([this, hook]
		(guest_virtual_processor_t& step_processor, const vmexit_context_t& step_context) -> bool
		{
			const address_type rip = step_context.processor_state.rip;

			block_pending_single_step_exception(step_processor);

			if (!hook->in_aligned_range(rip))
			{
				spdlog::info("left hooked page (rip=0x{:X})", rip);

				shadow_guest_interrupts(step_processor, false);

				protect_block_code_hook_memory_range(hook->start_address, hook->end_address, true);

				return false;
			}

			if (step_context.reason == vmexit_reason_t::exception)
			{
				const exception_vmexit_t info = step_context.exception;

				invoke_block_code_hook_step_callback(hook, rip, info.instruction_bytes);
			}
			else
			{
				std::array<std::uint8_t, max_instruction_length> instruction_bytes;

				std::ranges::fill(instruction_bytes, 0x90);

				if (step_processor.read_memory(rip, instruction_bytes))
				{
					invoke_block_code_hook_step_callback(hook, rip, instruction_bytes);
				}
			}

			shadow_guest_interrupts(step_processor, true);
		
			return true;
		});
}

void hm::emulator_t::invoke_block_code_hook_step_callback(const std::shared_ptr<hook_t>& hook, const address_type rip,
                                                          const std::span<const std::uint8_t> instruction_bytes)
{
	if (hook->in_range(rip))
	{
		const auto& hook_callback = std::get<hook_t::code_callback>(hook->callback);

		if (hook->type == hook_type_t::code)
		{
			hook_callback();
		}
		else
		{
			hook_basic_block_t& extra_data = std::get<hook_basic_block_t>(hook->extra_data);

			if (extra_data.was_control_flow)
			{
				hook_callback();

				extra_data.was_control_flow = false;
			}
			else
			{
				if (is_control_flow_instruction(mode_, instruction_bytes))
				{
					extra_data.was_control_flow = true;
				}
			}
		}
	}
}

bool hm::emulator_t::protect_block_code_hook_memory_range(const address_type start_address,
                                                          const address_type end_address, const bool executable)
{
	const address_type start_page_address = align_down(start_address, page_size);
	const address_type end_page_address = align_up(end_address, page_size);

	for (address_type i = start_page_address; i < end_page_address; i += page_size)
	{
		const auto protection = partition_->query_physical_memory_protection(i);

		if (!protection || (!executable && (*protection & prot_execute) == 0))
		{
			return false;
		}

		const protection_type new_protection = executable ? (*protection | prot_execute) : (*protection & ~prot_execute);

		partition_->protect_physical_memory(i, page_size, new_protection);
	}

	return true;
}

bool hm::emulator_t::memory_process_block_code_hook(guest_virtual_processor_t& processor, vmexit_context_t& context,
                                                    const std::shared_ptr<hook_t>& hook)
{
	const memory_vmexit_t& info = context.memory_access;
	const address_type rip = context.processor_state.rip;

	if (info.type == memory_vmexit_t::access_t::execute &&
		hook->in_aligned_range(rip))
	{
		spdlog::info("entered hooked page (rip=0x{:X})", rip);

		protect_block_code_hook_memory_range(hook->start_address, hook->end_address, true);

		set_block_code_hook_step(hook);

		invoke_block_code_hook_step_callback(hook, rip, info.instruction_bytes);

		set_trap_flag(processor, true);
		shadow_guest_interrupts(processor, true);
		block_pending_single_step_exception(processor);

		return true;
	}

	return false;
}

void hm::emulator_t::set_memory_hook_step(guest_virtual_processor_t& processor, vmexit_context_t& context,
                                          const std::shared_ptr<hook_t>& hook, bool& step_handled)
{
	const auto& hook_memory = std::get<hook_memory_t>(hook->extra_data);

	const memory_vmexit_t& info = context.memory_access;
	const address_type accessed_address = info.physical_address;

	const address_type page_address = align_down(accessed_address, page_size);

	address_type physical_page_address = page_address;

	if (processor.uses_paging())
	{
		const auto translation_result = partition_->translate_virtual_address(processor, page_address);

		if (!translation_result)
		{
			return;
		}

		physical_page_address = *translation_result;
	}

	protect_physical_memory(physical_page_address, page_size, prot_all);

	set_trap_flag(processor, true);

	single_step_callbacks_.emplace_back([this, hook_memory, physical_page_address]
		(guest_virtual_processor_t& step_processor, [[maybe_unused]] const vmexit_context_t& step_context) -> bool
		{
			const protection_type reverted_protection = prot_all & ~hook_memory.protection;

			protect_physical_memory(physical_page_address, page_size, reverted_protection);

			block_pending_single_step_exception(step_processor);
			shadow_guest_interrupts(step_processor, true);

			return false;
		});

	step_handled = true;
}

bool hm::emulator_t::memory_process_memory_hook(guest_virtual_processor_t& processor, vmexit_context_t& context,
                                                const std::shared_ptr<hook_t>& hook, bool& step_handled)
{
	const memory_vmexit_t& info = context.memory_access;
	const auto& hook_memory = std::get<hook_memory_t>(hook->extra_data);

	if (!hook_memory.exits_on(info.type))
	{
		return false;
	}

	const address_type accessed_address = info.physical_address;
	const bool is_invalid = !partition_->is_physical_address_valid(accessed_address);

	if (!hook->in_range(accessed_address))
	{
		if (!step_handled && hook->type == hook_type_t::memory_access && hook->in_aligned_range(accessed_address))
		{
			set_memory_hook_step(processor, context, hook, step_handled);
		}

		return false;
	}

	if (hook->type == hook_type_t::invalid_memory && is_invalid)
	{
		const auto& hook_callback = std::get<hook_t::invalid_memory_callback>(hook->callback);

		if (hook_callback(accessed_address, info.type))
		{
			return true;
		}
	}
	else if (hook->type == hook_type_t::memory_access && !is_invalid)
	{
		const auto& hook_callback = std::get<hook_t::memory_access_callback>(hook->callback);

		hook_callback(accessed_address, info.type);

		set_memory_hook_step(processor, context, hook, step_handled);

		return true;
	}

	return false;
}

bool hm::emulator_t::handle_cpuid_instruction(guest_virtual_processor_t& processor, vmexit_context_t& context)
{
	const address_type rip = context.processor_state.rip;

	bool should_skip = false;

	for (const auto& hook : hooks_)
	{
		if (hook->type != hook_type_t::instruction)
		{
			continue;
		}

		const auto hook_instruction = std::get<hook_instruction_t>(hook->extra_data);

		if (hook_instruction != hook_instruction_t::cpuid ||
			!hook->in_range(rip))
		{
			continue;
		}

		const auto& hook_callback = std::get<hook_t::instruction_callback>(hook->callback);

		if (hook_callback() && !should_skip)
		{
			should_skip = true;
		}
	}

	if (!should_skip)
	{
		const cpuid_vmexit_t info = context.cpuid;

		processor.write_register<reg::rax>(info.result_rax);
		processor.write_register<reg::rcx>(info.result_rcx);
		processor.write_register<reg::rdx>(info.result_rdx);
		processor.write_register<reg::rbx>(info.result_rbx);
	}

	context.advance_rip(processor);

	single_step(processor, context);

	return true;
}

bool hm::emulator_t::handle_rdtsc_instruction(guest_virtual_processor_t& processor, vmexit_context_t& context)
{
	const address_type rip = context.processor_state.rip;

	bool should_skip = false;

	for (const auto& hook : hooks_)
	{
		if (hook->type != hook_type_t::instruction)
		{
			continue;
		}

		const auto hook_instruction = std::get<hook_instruction_t>(hook->extra_data);

		if (hook_instruction != hook_instruction_t::rdtsc ||
			!hook->in_range(rip))
		{
			continue;
		}

		const auto& hook_callback = std::get<hook_t::instruction_callback>(hook->callback);

		if (hook_callback() && !should_skip)
		{
			should_skip = true;
		}
	}

	if (!should_skip)
	{
		const rdtsc_vmexit_t info = context.rdtsc;

		// todo: check if Hyper-V handles flags like
		// CR4.timestamp_disable for the partition

		const std::uint64_t tsc = info.tsc + info.virtual_offset;

		write_register<reg::rax>(tsc & 0xFFFFFFFF);
		write_register<reg::rdx>(tsc & 0xFFFFFFFF);

		if (info.is_rdtscp)
		{
			const std::uint64_t tsc_aux = info.tsc_aux + info.virtual_offset;

			write_register<reg::rcx>(tsc_aux);
		}
	}

	context.advance_rip(processor);

	single_step(processor, context);

	return true;
}

std::shared_ptr<hm::hook_t> hm::emulator_t::hook_instruction(const hook_instruction_t instruction,
                                                             const hook_t::instruction_callback& callback,
                                                             const address_type start_address,
                                                             const address_type end_address)
{
	if ((instruction == hook_instruction_t::cpuid && partition_->set_cpuid_exiting(true)) ||
		(instruction == hook_instruction_t::rdtsc && partition_->set_rdtsc_exiting(true)))
	{
		return add_hook(callback, hook_type_t::instruction, start_address, end_address, instruction);
	}

	return { };
}

std::shared_ptr<hm::hook_t> hm::emulator_t::hook_memory(const protection_type protection,
                                                        const hook_t::memory_access_callback& callback,
                                                        const address_type start_address,
                                                        const address_type end_address)
{
	if (!configure_single_step())
	{
		return { };
	}

	const address_type aligned_start = align_down(start_address, page_size);
	const address_type aligned_end = align_up(end_address, page_size);

	for (address_type i = aligned_start; i < aligned_end; i += page_size)
	{
		const auto current_protection = partition_->query_physical_memory_protection(i);

		if (!current_protection)
		{
			return { };
		}

		const protection_type new_protection = *current_protection & ~protection;

		if (!partition_->protect_physical_memory(i, page_size, new_protection))
		{
			return { };
		}
	}

	const hook_memory_t extra_data = {
		.protection = static_cast<protection_t>(protection)
	};

	return add_hook(callback, hook_type_t::memory_access, start_address, end_address, extra_data);
}

std::shared_ptr<hm::hook_t> hm::emulator_t::hook_invalid_memory(const protection_type protection,
                                                                const hook_t::invalid_memory_callback& callback,
                                                                const address_type start_address,
                                                                const address_type end_address)
{
	const hook_memory_t extra_data = {
		.protection = static_cast<protection_t>(protection)
	};

	return add_hook(callback, hook_type_t::invalid_memory, start_address, end_address, extra_data);
}

bool hm::emulator_t::remove_hook(const std::shared_ptr<hook_t>& hook)
{
	return std::erase(hooks_, hook) != 0;
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

bool hm::emulator_t::create_default_page_tables()
{
	constexpr address_type pml4_mapping = reserved_base + page_size;
	constexpr address_type pdpt_mapping = pml4_mapping + page_size;

	if (!map_physical_memory(pml4_mapping, page_size * 2, prot_read_write))
	{
		return false;
	}

	constexpr size_type pte_count = 512;

	std::array<pml4e_64, pte_count> pml4 = { };
	std::array<pdpte_1gb_64, pte_count> pdpt = { };

	pml4e_64& pml4e = pml4[0];

	pml4e.present = 1;
	pml4e.write = 1;
	pml4e.page_frame_number = pdpt_mapping >> 12;

	for (std::uint64_t i = 0; i < pte_count; i++)
	{
		pdpte_1gb_64& pdpte = pdpt[i];

		pdpte.present = 1;
		pdpte.write = 1;
		pdpte.large_page = 1;
		pdpte.page_frame_number = i;
	}

	if (!write_physical_memory(pml4_mapping, pml4.data(), sizeof(pml4)) ||
		!write_physical_memory(pdpt_mapping, pdpt.data(), sizeof(pdpt)))
	{
		return false;
	}

	write_register<reg::cr3>(pml4_mapping);

	return true;
}
