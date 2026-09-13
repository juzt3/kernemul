#include "emulator.hpp"
#include "../arch/decoder.hpp"

#include <ia32.hpp>
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

static bool is_control_flow_insn(const hm::machine_mode mode, const std::span<const std::uint8_t> insn_bytes)
{
	const auto raw_insn = hm::decode_insn(mode, insn_bytes);

	if (!raw_insn)
	{
		return false;
	}

	return raw_insn->is_jump() || raw_insn->is_call() ||
		raw_insn->is_ret() || raw_insn->is_interrupt() ||
		raw_insn->is_syscall();
};

static void set_trap_flag(hm::vcpu& cpu, const bool state)
{
	rflags current_flags = cpu.reg_read<hm::reg::rflags, rflags>();

	current_flags.trap_flag = state;

	cpu.reg_write<hm::reg::rflags>(current_flags);
}

static void shadow_guest_interrupts(hm::vcpu& cpu, const bool state)
{
	auto interrupt_state = cpu.reg_read<hm::reg::interrupt_state, WHV_X64_INTERRUPT_STATE_REGISTER>();

	interrupt_state.InterruptShadow = state;

	cpu.reg_write<hm::reg::interrupt_state>(interrupt_state);
}

static void block_pending_single_step_exception(hm::vcpu& cpu)
{
	auto debug_exception = cpu.reg_read<hm::reg::pending_debug_exception, WHV_X64_PENDING_DEBUG_EXCEPTION>();

	debug_exception.SingleStep = 0;

	cpu.reg_write<hm::reg::pending_debug_exception>(debug_exception);
}

static void inject_guest_exception(hm::vcpu& cpu, const std::uint16_t vector)
{
	WHV_X64_PENDING_EXCEPTION_EVENT event = { };

	event.EventPending = 1;
	event.EventType = WHvX64PendingEventException;
	event.Vector = vector;

	cpu.reg_write<hm::reg::pending_event>(event);
}

void hm::emu::single_step(vcpu& cpu, vmexit_context& context)
{
	const bool has_cbs = !single_step_cbs_.empty();

	for (std::uint32_t i = 0; i < single_step_cbs_.size(); i++)
	{
		const auto it = single_step_cbs_.begin() + i;

		if ((*it)(cpu, context) == false)
		{
			single_step_cbs_.erase(it);

			i--;
		}
	}

	// todo: find a way to check if the trap flag was set by the emulator
	if (context.reason == vmexit_reason::exception &&
		context.exception.id == exception_id::debug_trap)
	{
		set_trap_flag(cpu, !single_step_cbs_.empty());

		// No step callback was waiting on this trap, so the trap flag was the
		// guest's own. An exception hook gets it before the guest IDT does.
		if (!has_cbs && !dispatch_excp_hooks(exception_id::debug_trap))
		{
			inject_guest_exception(cpu, 1);
		}
	}
}

bool hm::emu::handle_page_fault(vcpu& cpu, const vmexit_context& context)
{
	const exception_vmexit& info = context.exception;

	if (!info.error_code)
	{
		return false;
	}

	const page_fault_exception error_code = { .flags = *info.error_code };
	const addr_t accessed_addr = info.exception_parameter;

	mem_vmexit::access access;

	if (error_code.execute)
	{
		access = mem_vmexit::access::execute;
	}
	else if (error_code.write)
	{
		access = mem_vmexit::access::write;
	}
	else
	{
		access = mem_vmexit::access::read;
	}

	bool handled = false;

	for (std::size_t i = 0; i < hooks_.size(); i++)
	{
		const auto& hook = hooks_[i];

		if (hook->type != hook_type::invalid_mem)
		{
			continue;
		}

		handled |= raw_process_invalid_mem_hook(hook, accessed_addr, access);
	}

	return handled;
}

std::shared_ptr<hm::emu_hook> hm::emu::hook_code(const emu_hook::code_hk_cb& cb,
                                                      const addr_t start_phys_addr,
                                                      const addr_t end_phys_addr)
{
	if (!configure_single_step())
	{
		return { };
	}

	const addr_t aligned_phys_start = align_down(start_phys_addr, page_size);
	const addr_t aligned_phys_end = align_up(end_phys_addr, page_size);

	const std::size_t aligned_size = aligned_phys_end - aligned_phys_start;

	// todo: go page by page on the protections
	if (!partition_->prot_phys_mem(aligned_phys_start, aligned_size, prot_rw))
	{
		return { };
	}

	return add_hook(cb, hook_type::code, start_phys_addr, end_phys_addr);
}

std::shared_ptr<hm::emu_hook> hm::emu::hook_basic_block(const emu_hook::code_hk_cb& cb,
                                                             const addr_t start_phys_addr,
                                                             const addr_t end_phys_addr)
{
	if (!configure_single_step())
	{
		return { };
	}

	const addr_t aligned_start = align_down(start_phys_addr, page_size);
	const addr_t aligned_end = align_up(end_phys_addr, page_size);

	for (addr_t i = aligned_start; i < aligned_end; i += page_size)
	{
		const auto current_prot = partition_->query_phys_mem_prot(i);

		if (!current_prot)
		{
			return { };
		}

		const mem_prot new_prot = *current_prot & ~prot_exec;

		if (!partition_->prot_phys_mem(i, page_size, new_prot))
		{
			return { };
		}
	}

	return add_hook(cb, hook_type::basic_block, start_phys_addr, end_phys_addr);
}

bool hm::emu::handle_exception(vcpu& cpu, vmexit_context& context)
{
	const exception_vmexit& info = context.exception;

	if (info.id == exception_id::debug_trap)
	{
		// single_step consults the exception hooks itself, since only it can
		// tell a trap of its own making from one the guest asked for.
		single_step(cpu, context);

		return true;
	}

	// An invalid-memory hook may still map the page in and retry the access.
	if (info.id == exception_id::page_fault && handle_page_fault(cpu, context))
	{
		return true;
	}

	// Nothing internal claimed it. Unclaimed by an exception hook too, it stops
	// the processor: delivering it blind through the guest IDT would fault
	// again at the same address for ever.
	return dispatch_excp_hooks(info.id);
}

bool hm::emu::dispatch_excp_hooks(const exception_id id)
{
	bool handled = false;

	for (std::size_t i = 0; i < hooks_.size(); i++)
	{
		const auto hook = hooks_[i];

		if (hook->type != hook_type::exception)
		{
			continue;
		}

		const auto& cb = std::get<emu_hook::excp_hk_cb>(hook->cb);

		handled |= cb(id);
	}

	return handled;
}

std::shared_ptr<hm::emu_hook> hm::emu::hook_exception(const emu_hook::excp_hk_cb& cb)
{
	// Every vector the partition can hand over. Debug traps included: with a
	// hook installed a guest-set trap flag is the hook's to interpret, not the
	// guest IDT's.
	if (!partition_->set_divide_error_exception_exiting(true) ||
		!partition_->set_debug_exception_exiting(true) ||
		!partition_->set_breakpoint_exception_exiting(true) ||
		!partition_->set_invalid_opcode_exception_exiting(true) ||
		!partition_->set_general_protection_exception_exiting(true) ||
		!partition_->set_page_fault_exception_exiting(true))
	{
		return { };
	}

	return add_hook(cb, hook_type::exception, default_start_addr, default_end_addr);
}

void hm::emu::resolve_mem_access_addr(vcpu& cpu, vmexit_context& context)
{
	mem_vmexit& info = context.mem_access;

	if (info.virt_addr_valid || !cpu.uses_paging())
	{
		return;
	}

	auto insn_bytes = info.insn_bytes;

	if (const bool bytes_are_empty = std::ranges::all_of(insn_bytes, [](std::uint8_t b) { return b == 0; }))
	{
		const auto phys_rip = context.cpu_state.phys_rip(cpu);

		if (phys_rip)
		{
			partition_->read_phys_mem(*phys_rip, insn_bytes);
		}
	}

	const auto insn = hm::decode_insn_full(mode_, insn_bytes);

	if (!insn)
	{
		return;
	}

	ZydisRegisterContext register_context = { };

	const auto populate_gpr = [&](ZydisRegister r64, ZydisRegister r32, ZydisRegister r16,
		ZydisRegister r8h, ZydisRegister r8l, std::uint64_t value)
		{
			register_context.values[r64] = value;
			register_context.values[r32] = value & 0xFFFFFFFF;
			register_context.values[r16] = value & 0xFFFF;

			if (r8l != ZYDIS_REGISTER_NONE)
			{
				register_context.values[r8l] = value & 0xFF;
			}

			if (r8h != ZYDIS_REGISTER_NONE)
			{
				register_context.values[r8h] = (value >> 8) & 0xFF;
			}
		};

	populate_gpr(ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_EAX, ZYDIS_REGISTER_AX, ZYDIS_REGISTER_AH, ZYDIS_REGISTER_AL, cpu.reg_read<reg::rax, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_ECX, ZYDIS_REGISTER_CX, ZYDIS_REGISTER_CH, ZYDIS_REGISTER_CL, cpu.reg_read<reg::rcx, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_EDX, ZYDIS_REGISTER_DX, ZYDIS_REGISTER_DH, ZYDIS_REGISTER_DL, cpu.reg_read<reg::rdx, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_EBX, ZYDIS_REGISTER_BX, ZYDIS_REGISTER_BH, ZYDIS_REGISTER_BL, cpu.reg_read<reg::rbx, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_ESP, ZYDIS_REGISTER_SP, ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_SPL, cpu.reg_read<reg::rsp, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_EBP, ZYDIS_REGISTER_BP, ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_BPL, cpu.reg_read<reg::rbp, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_ESI, ZYDIS_REGISTER_SI, ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_SIL, cpu.reg_read<reg::rsi, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_EDI, ZYDIS_REGISTER_DI, ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_DIL, cpu.reg_read<reg::rdi, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R8D, ZYDIS_REGISTER_R8W, ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_R8B, cpu.reg_read<reg::r8, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R9D, ZYDIS_REGISTER_R9W, ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_R9B, cpu.reg_read<reg::r9, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R10D, ZYDIS_REGISTER_R10W, ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_R10B, cpu.reg_read<reg::r10, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_R11, ZYDIS_REGISTER_R11D, ZYDIS_REGISTER_R11W, ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_R11B, cpu.reg_read<reg::r11, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R12D, ZYDIS_REGISTER_R12W, ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_R12B, cpu.reg_read<reg::r12, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R13D, ZYDIS_REGISTER_R13W, ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_R13B, cpu.reg_read<reg::r13, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R14D, ZYDIS_REGISTER_R14W, ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_R14B, cpu.reg_read<reg::r14, std::uint64_t>());
	populate_gpr(ZYDIS_REGISTER_R15, ZYDIS_REGISTER_R15D, ZYDIS_REGISTER_R15W, ZYDIS_REGISTER_NONE, ZYDIS_REGISTER_R15B, cpu.reg_read<reg::r15, std::uint64_t>());

	register_context.values[ZYDIS_REGISTER_RIP] = context.cpu_state.rip;
	register_context.values[ZYDIS_REGISTER_EIP] = context.cpu_state.rip & 0xFFFFFFFF;
	register_context.values[ZYDIS_REGISTER_IP] = context.cpu_state.rip & 0xFFFF;

	register_context.values[ZYDIS_REGISTER_RFLAGS] = cpu.reg_read<reg::rflags, std::uint64_t>();

	const std::pair<ZydisRegister, std::uint64_t> segment_bases[] = {
		{ ZYDIS_REGISTER_ES, cpu.reg_read<reg::es, WHV_X64_SEGMENT_REGISTER>().Base },
		{ ZYDIS_REGISTER_CS, cpu.reg_read<reg::cs, WHV_X64_SEGMENT_REGISTER>().Base },
		{ ZYDIS_REGISTER_SS, cpu.reg_read<reg::ss, WHV_X64_SEGMENT_REGISTER>().Base },
		{ ZYDIS_REGISTER_DS, cpu.reg_read<reg::ds, WHV_X64_SEGMENT_REGISTER>().Base },
		{ ZYDIS_REGISTER_FS, cpu.reg_read<reg::fs, WHV_X64_SEGMENT_REGISTER>().Base },
		{ ZYDIS_REGISTER_GS, cpu.reg_read<reg::gs, WHV_X64_SEGMENT_REGISTER>().Base },
	};

	for (const auto& operand : insn->visible_operands())
	{
		if (operand.type() != decoded_operand::op_type::mem)
		{
			continue;
		}

		const auto& raw_operand = static_cast<const ZydisDecodedOperand&>(operand);

		ZyanU64 resolved_addr = 0;

		if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddressEx(&insn->raw(), &raw_operand, context.cpu_state.rip, &register_context, &resolved_addr)))
		{
			continue;
		}

		for (const auto& [seg_reg, seg_base] : segment_bases)
		{
			if (raw_operand.mem.segment == seg_reg)
			{
				resolved_addr += seg_base;
				break;
			}
		}

		const auto translated = cpu.virt_to_phys(resolved_addr);

		if (translated && *translated == info.phys_addr)
		{
			info.virt_addr = resolved_addr;
			info.virt_addr_valid = true;

			return;
		}
	}
}

bool hm::emu::handle_mem_access(vcpu& cpu, vmexit_context& context)
{
	bool handled = false;
	bool step_handled = false;

	resolve_mem_access_addr(cpu, context);

	const auto valid_rip = context.cpu_state.phys_rip(cpu).has_value();

	for (std::size_t i = 0; i < hooks_.size(); i++)
	{
		const auto hook = hooks_[i];

		switch (hook->type)
		{
		case hook_type::code:
		case hook_type::basic_block:
			handled |= mem_process_block_code_hook(cpu, context, hook);
			break;
		case hook_type::mem_access:
			handled |= valid_rip && mem_process_mem_hook(cpu, context, hook, step_handled);
			break;
		case hook_type::invalid_mem:
			handled |= mem_process_mem_hook(cpu, context, hook, step_handled);
			break;
		default:
			break;
		}
	}

	return handled;
}

void hm::emu::set_block_code_hook_step(const std::shared_ptr<emu_hook>& hook)
{
	single_step_cbs_.emplace_back([this, hook]
		(vcpu& step_cpu, const vmexit_context& step_context) -> bool
		{
			const auto rip = step_context.cpu_state.phys_rip(step_cpu);

			if (!rip)
			{
				return false;
			}

			block_pending_single_step_exception(step_cpu);

			auto active_hook = hook;

			if (!active_hook->in_aligned_range(*rip, step_context.cpu_state.insn_len))
			{
				std::shared_ptr<emu_hook> sibling_hook;

				for (const auto& candidate : hooks_)
				{
					if (candidate.get() != hook.get()
						&& (candidate->type == hook_type::basic_block || candidate->type == hook_type::code)
						&& candidate->in_aligned_range(*rip, step_context.cpu_state.insn_len))
					{
						sibling_hook = candidate;
						break;
					}
				}

				if (!sibling_hook)
				{
					shadow_guest_interrupts(step_cpu, false);

					prot_block_code_hook_mem_range(hook->start_addr, hook->end_addr, false);

					return false;
				}

				prot_block_code_hook_mem_range(hook->start_addr, hook->end_addr, false);
				prot_block_code_hook_mem_range(sibling_hook->start_addr, sibling_hook->end_addr, true);

				active_hook = sibling_hook;
			}

			const auto virt_rip = step_context.cpu_state.rip;
			const std::size_t virt_page_offset = virt_rip % page_size;
			const std::size_t bytes_until_page_end = page_size - virt_page_offset;

			addr_t adjacent_phys_page = 0;
			bool enabled_adjacent = false;

			if (bytes_until_page_end < max_insn_len)
			{
				const auto next_virt_page = align_down(virt_rip, page_size) + page_size;
				const auto next_phys = partition_->virt_to_phys(step_cpu, next_virt_page);

				if (next_phys)
				{
					adjacent_phys_page = align_down(*next_phys, page_size);
					const auto prot = partition_->query_phys_mem_prot(adjacent_phys_page);

					if (prot && !(*prot & prot_exec))
					{
						partition_->prot_phys_mem(adjacent_phys_page, page_size, *prot | prot_exec);
						enabled_adjacent = true;
					}
				}
			}

			if (step_context.reason == vmexit_reason::exception)
			{
				const exception_vmexit info = step_context.exception;

				invoke_block_code_hook_step_cb(active_hook, *rip, info.insn_bytes);
			}
			else
			{
				std::array<std::uint8_t, max_insn_len> insn_bytes;

				std::ranges::fill(insn_bytes, 0x90);

				if (step_cpu.read_mem(*rip, insn_bytes))
				{
					invoke_block_code_hook_step_cb(active_hook, *rip, insn_bytes);
				}
			}

			if (enabled_adjacent)
			{
				const auto prot = partition_->query_phys_mem_prot(adjacent_phys_page);

				if (prot)
				{
					partition_->prot_phys_mem(adjacent_phys_page, page_size, *prot & ~prot_exec);
				}
			}

			shadow_guest_interrupts(step_cpu, true);
		
			return true;
		});
}

void hm::emu::handle_block_hook_overflow([[maybe_unused]] const std::shared_ptr<emu_hook>& hook, const addr_t rip)
{
	const std::size_t page_offset = rip % page_size;

	if (max_insn_len < page_offset)
	{
		block_hook_was_control_flow_ = true;
	}
}

void hm::emu::invoke_block_code_hook_step_cb(const std::shared_ptr<emu_hook>& hook, const addr_t rip,
                                                          const std::span<const std::uint8_t> insn_bytes)
{
	if (hook->in_range(rip))
	{
		const auto& cb = std::get<emu_hook::code_hk_cb>(hook->cb);

		if (hook->type == hook_type::code)
		{
			cb();
		}
		else
		{
			if (block_hook_was_control_flow_)
			{
				cb();

				block_hook_was_control_flow_ = false;
			}
			else if (is_control_flow_insn(mode_, insn_bytes))
			{
				block_hook_was_control_flow_ = true;
			}
		}
	}
}

bool hm::emu::prot_block_code_hook_mem_range(const addr_t start_addr,
                                                          const addr_t end_addr, const bool executable)
{
	const addr_t start_page_addr = align_down(start_addr, page_size);
	const addr_t end_page_addr = align_up(end_addr, page_size);

	// one page below, one page above
	const addr_t end_added = end_page_addr + page_size;

	const addr_t start = page_size <= start_page_addr ? start_page_addr - page_size : 0;
	const addr_t end = end_added < end_page_addr ? end_page_addr : end_added;

	for (addr_t i = start; i < end; i += page_size)
	{
		const auto prot = partition_->query_phys_mem_prot(i);

		if (!prot || (!executable && (*prot & prot_exec) == 0))
		{
			continue;
		}

		const mem_prot new_prot = executable ? (*prot | prot_exec) : (*prot & ~prot_exec);

		partition_->prot_phys_mem(i, page_size, new_prot);
	}

	return true;
}

bool hm::emu::mem_process_block_code_hook(vcpu& cpu, vmexit_context& context,
                                                    const std::shared_ptr<emu_hook>& hook)
{
	const mem_vmexit& info = context.mem_access;
	const auto rip = context.cpu_state.phys_rip(cpu);

	if (!rip)
	{
		return false;
	}

	if (info.type == mem_vmexit::access::execute && hook->in_aligned_range(*rip, max_insn_len))
	{
		prot_block_code_hook_mem_range(hook->start_addr, hook->end_addr, true);

		const auto virt_rip = context.cpu_state.rip;
		const std::size_t page_offset = virt_rip % page_size;
		const std::size_t bytes_until_page_end = page_size - page_offset;

		if (bytes_until_page_end < max_insn_len)
		{
			const auto next_virt_page = align_down(virt_rip, page_size) + page_size;
			const auto next_phys_page = partition_->virt_to_phys(cpu, next_virt_page);

			if (next_phys_page)
			{
				const auto next_phys_page_aligned = align_down(*next_phys_page, page_size);
				const auto prot = partition_->query_phys_mem_prot(next_phys_page_aligned);

				if (prot)
				{
					partition_->prot_phys_mem(next_phys_page_aligned, page_size, *prot | prot_exec);
				}
			}
		}

		set_block_code_hook_step(hook);

		if (hook->type == hook_type::basic_block)
		{
			handle_block_hook_overflow(hook, *rip);
		}

		set_trap_flag(cpu, true);
		shadow_guest_interrupts(cpu, true);
		block_pending_single_step_exception(cpu);

		if (hook->in_aligned_range(*rip))
		{
			invoke_block_code_hook_step_cb(hook, *rip, info.insn_bytes);
		}

		return true;
	}

	return false;
}

void hm::emu::set_mem_hook_step(vcpu& cpu, vmexit_context& context,
                                          const std::shared_ptr<emu_hook>& hook, bool& step_handled)
{
	const auto& hook_mem = std::get<hook_mem_t>(hook->extra_data);

	const mem_vmexit& info = context.mem_access;
	const addr_t accessed_addr = info.phys_addr;

	const addr_t page_addr = align_down(accessed_addr, page_size);

	prot_phys_mem(page_addr, page_size, prot_rwx);

	set_trap_flag(cpu, true);

	single_step_cbs_.emplace_back([this, hook_mem, page_addr]
		(vcpu& step_cpu, [[maybe_unused]] const vmexit_context& step_context) -> bool
		{
			const mem_prot reverted_prot = prot_rwx & ~hook_mem.prot;

			prot_phys_mem(page_addr, page_size, reverted_prot);

			block_pending_single_step_exception(step_cpu);
			shadow_guest_interrupts(step_cpu, true);

			return false;
		});

	step_handled = true;
}

bool hm::emu::mem_process_mem_hook(vcpu& cpu, vmexit_context& context,
                                                const std::shared_ptr<emu_hook>& hook, bool& step_handled)
{
	const mem_vmexit& info = context.mem_access;

	const addr_t symbolic_accessed_addr = info.virt_addr_valid ? info.virt_addr : info.phys_addr;

	if (hook->type == hook_type::invalid_mem)
	{
		if (!partition_->is_phys_addr_valid(info.phys_addr))
		{
			return raw_process_invalid_mem_hook(hook, symbolic_accessed_addr, info.type);
		}

		return false;
	}

	// hook_type::mem_access
	const auto& hook_mem = std::get<hook_mem_t>(hook->extra_data);

	if (!hook_mem.exits_on(info.type))
	{
		return false;
	}

	const addr_t phys_accessed_addr = info.phys_addr;

	if (!hook->in_range(phys_accessed_addr))
	{
		if (!step_handled && hook->type == hook_type::mem_access && hook->in_aligned_range(phys_accessed_addr))
		{
			set_mem_hook_step(cpu, context, hook, step_handled);

			return true;
		}

		return false;
	}

	const auto& cb = std::get<emu_hook::mem_hk_cb>(hook->cb);

	cb(symbolic_accessed_addr, info.type);

	if (pending_single_step_cancelled_)
	{
		pending_single_step_cancelled_ = false;
		block_pending_single_step_exception(cpu);
		set_trap_flag(cpu, false);
		step_handled = true;
	}
	else
	{
		set_mem_hook_step(cpu, context, hook, step_handled);
	}

	return true;
}

bool hm::emu::raw_process_invalid_mem_hook(const std::shared_ptr<emu_hook>& hook,
                                                     const addr_t accessed_addr,
                                                     const mem_vmexit::access access_type)
{
	const auto& hook_mem = std::get<hook_mem_t>(hook->extra_data);

	if (!hook_mem.exits_on(access_type) || !hook->in_range(accessed_addr))
	{
		return false;
	}

	const auto& cb = std::get<emu_hook::invalid_mem_hk_cb>(hook->cb);

	return cb(accessed_addr, access_type);
}

bool hm::emu::handle_cpuid_insn(vcpu& cpu, vmexit_context& context)
{
	const addr_t rip = context.cpu_state.rip;

	bool should_skip = false;

	for (std::size_t i = 0; i < hooks_.size(); i++)
	{
		const auto& hook = hooks_[i];

		if (hook->type != hook_type::insn)
		{
			continue;
		}

		const auto hook_insn = std::get<hook_insn_t>(hook->extra_data);

		if (hook_insn != hook_insn_t::cpuid ||
			!hook->in_range(rip))
		{
			continue;
		}

		const auto& cb = std::get<emu_hook::insn_hk_cb>(hook->cb);

		if (cb() && !should_skip)
		{
			should_skip = true;
		}
	}

	if (!should_skip)
	{
		const cpuid_vmexit info = context.cpuid;

		cpu.reg_write<reg::rax>(info.result_rax);
		cpu.reg_write<reg::rcx>(info.result_rcx);
		cpu.reg_write<reg::rdx>(info.result_rdx);
		cpu.reg_write<reg::rbx>(info.result_rbx);
	}

	context.advance_rip(cpu);

	single_step(cpu, context);

	return true;
}

bool hm::emu::handle_rdtsc_insn(vcpu& cpu, vmexit_context& context)
{
	const addr_t rip = context.cpu_state.rip;

	bool should_skip = false;

	for (std::size_t i = 0; i < hooks_.size(); i++)
	{
		const auto& hook = hooks_[i];

		if (hook->type != hook_type::insn)
		{
			continue;
		}

		const auto hook_insn = std::get<hook_insn_t>(hook->extra_data);

		if (hook_insn != hook_insn_t::rdtsc ||
			!hook->in_range(rip))
		{
			continue;
		}

		const auto& cb = std::get<emu_hook::insn_hk_cb>(hook->cb);

		if (cb() && !should_skip)
		{
			should_skip = true;
		}
	}

	if (!should_skip)
	{
		const rdtsc_vmexit info = context.rdtsc;

		// todo: check if Hyper-V handles flags like
		// CR4.timestamp_disable for the partition

		const std::uint64_t tsc = info.tsc + info.virt_offset;

		reg_write<reg::rax>(tsc & 0xFFFFFFFF);
		reg_write<reg::rdx>((tsc >> 32) & 0xFFFFFFFF);

		if (info.is_rdtscp)
		{
			reg_write<reg::rcx>(info.tsc_aux);
		}
	}

	context.advance_rip(cpu);

	single_step(cpu, context);

	return true;
}

std::shared_ptr<hm::emu_hook> hm::emu::hook_insn(const hook_insn_t insn,
                                                             const emu_hook::insn_hk_cb& cb,
                                                             const addr_t start_addr,
                                                             const addr_t end_addr)
{
	if ((insn == hook_insn_t::cpuid && partition_->set_cpuid_exiting(true)) ||
		(insn == hook_insn_t::rdtsc && partition_->set_rdtsc_exiting(true)))
	{
		return add_hook(cb, hook_type::insn, start_addr, end_addr, insn);
	}

	return { };
}

std::shared_ptr<hm::emu_hook> hm::emu::hook_mem(const mem_prot prot,
                                                        const emu_hook::mem_hk_cb& cb,
                                                        const addr_t start_phys_addr,
                                                        const addr_t end_phys_addr)
{
	if (!configure_single_step())
	{
		return { };
	}

	const addr_t aligned_start = align_down(start_phys_addr, page_size);
	const addr_t aligned_end = align_up(end_phys_addr, page_size);

	for (addr_t i = aligned_start; i < aligned_end; i += page_size)
	{
		const auto current_prot = partition_->query_phys_mem_prot(i);

		if (!current_prot)
		{
			return { };
		}

		const mem_prot new_prot = *current_prot & ~prot;

		if (!partition_->prot_phys_mem(i, page_size, new_prot))
		{
			return { };
		}
	}

	const hook_mem_t extra_data = {
		.prot = static_cast<mem_prot>(prot)
	};

	return add_hook(cb, hook_type::mem_access, start_phys_addr, end_phys_addr, extra_data);
}

std::shared_ptr<hm::emu_hook> hm::emu::hook_invalid_mem(const mem_prot prot,
                                                                const emu_hook::invalid_mem_hk_cb& cb,
                                                                const addr_t start_addr,
                                                                const addr_t end_addr)
{
	if (!partition_->set_page_fault_exception_exiting(true))
	{
		return { };
	}

	const hook_mem_t extra_data = {
		.prot = static_cast<mem_prot>(prot)
	};

	return add_hook(cb, hook_type::invalid_mem, start_addr, end_addr, extra_data);
}

bool hm::emu::remove_hook(const std::shared_ptr<emu_hook>& hook)
{
	return std::erase(hooks_, hook) != 0;
}
