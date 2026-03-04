#include "emulator.hpp"
#include "../arch/decoder.hpp"

#include <ia32-doc/ia32.hpp>
#include <spdlog/spdlog.h>
#include <ranges>

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

bool hm::emulator_t::handle_page_fault(guest_virtual_processor_t& processor, const vmexit_context_t& context)
{
	const exception_vmexit_t& info = context.exception;

	if (!info.error_code)
	{
		return false;
	}

	const page_fault_exception error_code = { .flags = *info.error_code };
	const address_type accessed_address = info.exception_parameter;

	memory_vmexit_t::access access;

	if (error_code.execute)
	{
		access = memory_vmexit_t::access::execute;
	}
	else if (error_code.write)
	{
		access = memory_vmexit_t::access::write;
	}
	else
	{
		access = memory_vmexit_t::access::read;
	}

	bool handled = false;

	for (const auto& hook : hooks_)
	{
		if (hook->type != hook_type_t::invalid_memory)
		{
			continue;
		}

		handled |= raw_process_invalid_memory_hook(hook, accessed_address, access);
	}

	return handled;
}

std::shared_ptr<hm::hook_t> hm::emulator_t::hook_code(const hook_t::code_callback& callback,
                                                      const address_type start_physical_address,
                                                      const address_type end_physical_address)
{
	if (!configure_single_step())
	{
		return { };
	}

	const address_type aligned_physical_start = align_down(start_physical_address, page_size);
	const address_type aligned_physical_end = align_up(end_physical_address, page_size);

	const size_type aligned_size = aligned_physical_end - aligned_physical_start;

	// todo: go page by page on the protections
	if (!partition_->protect_physical_memory(aligned_physical_start, aligned_size, prot_read_write))
	{
		return { };
	}

	return add_hook(callback, hook_type_t::code, start_physical_address, end_physical_address);
}

std::shared_ptr<hm::hook_t> hm::emulator_t::hook_basic_block(const hook_t::code_callback& callback,
                                                             const address_type start_physical_address,
                                                             const address_type end_physical_address)
{
	if (!configure_single_step())
	{
		return { };
	}

	const address_type aligned_start = align_down(start_physical_address, page_size);
	const address_type aligned_end = align_up(end_physical_address, page_size);

	const size_type aligned_size = aligned_end - aligned_start;

	// todo: go page by page on the protections
	if (!partition_->protect_physical_memory(aligned_start, aligned_size, prot_read_write))
	{
		return { };
	}

	constexpr hook_basic_block_t extra_data = {
		.was_control_flow = false
	};

	return add_hook(callback, hook_type_t::basic_block, start_physical_address, end_physical_address, extra_data);
}

bool hm::emulator_t::handle_exception(guest_virtual_processor_t& processor, vmexit_context_t& context)
{
	const exception_vmexit_t& info = context.exception;

	if (info.id == exception_id_t::debug_trap)
	{
		single_step(processor, context);
	}
	else if (info.id == exception_id_t::page_fault)
	{
		return handle_page_fault(processor, context);
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
			const address_type rip = step_context.processor_state.physical_rip(step_processor);

			block_pending_single_step_exception(step_processor);

			if (!hook->in_aligned_range(rip))
			{
				//spdlog::info("left hooked page (rip=0x{:X})", step_context.processor_state.rip);

				shadow_guest_interrupts(step_processor, false);

				protect_block_code_hook_memory_range(hook->start_address, hook->end_address, false);

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

void hm::emulator_t::handle_block_hook_overflow(const std::shared_ptr<hook_t>& hook, const address_type rip)
{
	const size_type page_offset = rip % page_size;

	if (max_instruction_length < page_offset)
	{
		hook_basic_block_t& extra_data = std::get<hook_basic_block_t>(hook->extra_data);

		extra_data.was_control_flow = true;
	}
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

	// one page below, one page above
	const address_type end_added = end_page_address + page_size;

	const address_type start = page_size <= start_page_address ? start_page_address - page_size : 0;
	const address_type end = end_added < end_page_address ? end_page_address : end_added;

	for (address_type i = start; i < end; i += page_size)
	{
		const auto protection = partition_->query_physical_memory_protection(i);

		if (!protection || (!executable && (*protection & prot_execute) == 0))
		{
			continue;
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
	const address_type rip = context.processor_state.physical_rip(processor);

	if (info.type == memory_vmexit_t::access::execute &&
		hook->in_aligned_range(rip))
	{
		//spdlog::info("entered hooked page (rip=0x{:X})", context.processor_state.rip);

		protect_block_code_hook_memory_range(hook->start_address, hook->end_address, true);

		set_block_code_hook_step(hook);

		if (hook->type == hook_type_t::basic_block)
		{
			handle_block_hook_overflow(hook, rip);
		}

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

	protect_physical_memory(page_address, page_size, prot_all);

	set_trap_flag(processor, true);

	single_step_callbacks_.emplace_back([this, hook_memory, page_address]
		(guest_virtual_processor_t& step_processor, [[maybe_unused]] const vmexit_context_t& step_context) -> bool
		{
			const protection_type reverted_protection = prot_all & ~hook_memory.protection;

			protect_physical_memory(page_address, page_size, reverted_protection);

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

	const address_type symbolic_accessed_address = info.virtual_address_valid ? info.virtual_address : info.physical_address;

	if (hook->type == hook_type_t::invalid_memory)
	{
		if (!partition_->is_physical_address_valid(info.physical_address))
		{
			return raw_process_invalid_memory_hook(hook, symbolic_accessed_address, info.type);
		}

		return false;
	}

	// hook_type_t::memory_access
	const auto& hook_memory = std::get<hook_memory_t>(hook->extra_data);

	if (!hook_memory.exits_on(info.type))
	{
		return false;
	}

	const address_type real_phys_addr = processor.translate_virtual_address(info.virtual_address).value_or(1337);
	const address_type physical_accessed_address = info.physical_address;

	if (!hook->in_range(physical_accessed_address))
	{
		if (!step_handled && hook->type == hook_type_t::memory_access && hook->in_aligned_range(physical_accessed_address))
		{
			set_memory_hook_step(processor, context, hook, step_handled);

			return true;
		}

		return false;
	}

	const auto& hook_callback = std::get<hook_t::memory_access_callback>(hook->callback);

	hook_callback(symbolic_accessed_address, info.type);

	set_memory_hook_step(processor, context, hook, step_handled);

	return true;
}

bool hm::emulator_t::raw_process_invalid_memory_hook(const std::shared_ptr<hook_t>& hook,
                                                     const address_type accessed_address,
                                                     const memory_vmexit_t::access access_type)
{
	const auto& hook_memory = std::get<hook_memory_t>(hook->extra_data);

	if (!hook_memory.exits_on(access_type) || !hook->in_range(accessed_address))
	{
		return false;
	}

	const auto& hook_callback = std::get<hook_t::invalid_memory_callback>(hook->callback);

	return hook_callback(accessed_address, access_type);
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
                                                        const address_type start_physical_address,
                                                        const address_type end_physical_address)
{
	if (!configure_single_step())
	{
		return { };
	}

	const address_type aligned_start = align_down(start_physical_address, page_size);
	const address_type aligned_end = align_up(end_physical_address, page_size);

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

	return add_hook(callback, hook_type_t::memory_access, start_physical_address, end_physical_address, extra_data);
}

std::shared_ptr<hm::hook_t> hm::emulator_t::hook_invalid_memory(const protection_type protection,
                                                                const hook_t::invalid_memory_callback& callback,
                                                                const address_type start_address,
                                                                const address_type end_address)
{
	if (!partition_->set_page_fault_exception_exiting(true))
	{
		return { };
	}

	const hook_memory_t extra_data = {
		.protection = static_cast<protection_t>(protection)
	};

	return add_hook(callback, hook_type_t::invalid_memory, start_address, end_address, extra_data);
}

bool hm::emulator_t::remove_hook(const std::shared_ptr<hook_t>& hook)
{
	return std::erase(hooks_, hook) != 0;
}
