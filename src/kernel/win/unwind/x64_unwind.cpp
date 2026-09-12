#include "../../../target.hpp"
#if defined(KERNEMUL_ARCH_X64)
#include "x64_unwind.hpp"
#include "../exception.hpp"
#include "../../process.hpp"
#include "../../../emu/emu.hpp"
#include "../../../emu/x86/arch.hpp"
#include "../../../util/log.hpp"

namespace win {

using enum pe::unwind_opcode_x64;

static constexpr reg_t gp_to_reg[] = {
	x86::rax, x86::rcx, x86::rdx, x86::rbx,
	x86::rsp, x86::rbp, x86::rsi, x86::rdi,
	x86::r8,  x86::r9,  x86::r10, x86::r11,
	x86::r12, x86::r13, x86::r14, x86::r15,
};

unwind_context x64_unwinder::context_from_vcpu(vcpu& cpu)
{
	unwind_context ctx{};
	ctx.pc = cpu.pc();
	ctx.sp = cpu.sp();

	for (int i = 0; i < 16; ++i)
		ctx.gp[i] = cpu.reg(gp_to_reg[i]);

	return ctx;
}

std::optional<pe::runtime_function_x64> x64_unwinder::lookup_function_entry(
	const proc_module& mod, const addr_t rip)
{
	const auto* img = mod.pe();
	if (!img)
		return std::nullopt;

	const auto& exc = img->nt_hdrs()->optional_hdr.data_dirs.exception;
	if (!exc.used())
		return std::nullopt;

	const auto* base = img->as<const std::uint8_t*>();
	const auto* funcs = reinterpret_cast<const pe::runtime_function_x64*>(base + exc.virtual_address);
	const std::uint32_t count = exc.size / sizeof(pe::runtime_function_x64);
	const std::uint32_t rva = static_cast<std::uint32_t>(rip - mod.addr);

	std::uint32_t lo = 0, hi = count;

	while (lo < hi)
	{
		const auto mid = lo + (hi - lo) / 2;
		const auto& entry = funcs[mid];

		if (rva < entry.begin_address)
			hi = mid;
		else if (rva >= entry.end_address)
			lo = mid + 1;
		else
			return entry;
	}

	return std::nullopt;
}

static unwind_result apply_unwind_info(
	addr_space& mem, const proc_module& mod,
	const pe::runtime_function_x64& func, unwind_context& ctx)
{
	unwind_result result{};
	const auto* img_base = mod.pe()->as<const std::uint8_t*>();
	auto unwind_rva = func.unwind_info_rva;

	for (;;)
	{
		const auto* info = reinterpret_cast<const pe::unwind_info_x64*>(img_base + unwind_rva);
		const auto codes = info->code_list();

		const std::uint32_t rva_in_func =
			static_cast<std::uint32_t>(ctx.pc - mod.addr) - func.begin_address;
		const bool in_prolog = rva_in_func < info->size_of_prolog;

		if (info->frame_register != pe::unwind_register_x64::rax && !in_prolog)
			ctx.sp = ctx.gp[static_cast<int>(info->frame_register)] -
				static_cast<addr_t>(info->frame_offset) * 16;

		result.establisher_frame = ctx.sp;

		for (std::uint32_t i = 0; i < info->unwind_code_count; )
		{
			const auto& code = codes[i];
			const auto op = code.code;
			const auto reg = code.info;
			const auto n = code.slots();

			if (in_prolog && code.offset > rva_in_func)
			{
				i += static_cast<std::uint32_t>(n);
				continue;
			}

			switch (op)
			{
			case push_nonvol:
				ctx.gp[reg] = mem.read_mem<addr_t>(ctx.sp);
				ctx.sp += sizeof(std::uint64_t);
				break;

			case alloc_large:
				if (reg == 0)
					ctx.sp += static_cast<addr_t>(codes[i + 1].frame_offset) * sizeof(std::uint64_t);
				else
				{
					const auto lo = codes[i + 1].frame_offset;
					const auto hi = codes[i + 2].frame_offset;
					ctx.sp += static_cast<addr_t>(lo) | (static_cast<addr_t>(hi) << 16);
				}
				break;

			case alloc_small:
				ctx.sp += static_cast<addr_t>(reg) * sizeof(std::uint64_t) + sizeof(std::uint64_t);
				break;

			case set_fpreg:
				break;

			case save_nonvol:
			{
				const auto offset = codes[i + 1].frame_offset;
				ctx.gp[reg] = mem.read_mem<addr_t>(
					ctx.sp + static_cast<addr_t>(offset) * sizeof(std::uint64_t));
				break;
			}

			case save_nonvol_far:
			{
				const auto lo = codes[i + 1].frame_offset;
				const auto hi = codes[i + 2].frame_offset;
				const addr_t offset = static_cast<addr_t>(lo) |
					(static_cast<addr_t>(hi) << 16);
				ctx.gp[reg] = mem.read_mem<addr_t>(ctx.sp + offset);
				break;
			}

			case save_xmm128:
			case save_xmm128_far:
				break;

			case push_machframe:
				if (reg == 1)
					ctx.sp += sizeof(std::uint64_t);
				ctx.pc = mem.read_mem<addr_t>(ctx.sp);
				ctx.sp = mem.read_mem<addr_t>(ctx.sp + 24);
				ctx.gp[static_cast<int>(pe::unwind_register_x64::rsp)] = ctx.sp;
				return result;

			default:
				break;
			}

			i += static_cast<std::uint32_t>(n);
		}

		const auto padded_count = (info->unwind_code_count + 1u) & ~1u;
		const auto* after_codes = reinterpret_cast<const std::uint8_t*>(
			&info->codes[padded_count]);

		if (info->chain_info)
		{
			const auto* chained = reinterpret_cast<const pe::runtime_function_x64*>(after_codes);
			unwind_rva = chained->unwind_info_rva;
			continue;
		}

		if (info->exception_handler || info->unwind_handler)
		{
			const auto handler_rva = *reinterpret_cast<const std::uint32_t*>(after_codes);
			result.handler = mod.addr + handler_rva;
			result.handler_data = mod.addr +
				static_cast<addr_t>(after_codes + 4 - img_base);
		}

		ctx.pc = mem.read_mem<addr_t>(ctx.sp);
		ctx.sp += sizeof(std::uint64_t);
		break;
	}

	ctx.gp[static_cast<int>(pe::unwind_register_x64::rsp)] = ctx.sp;
	return result;
}

bool x64_unwinder::unwind_frame(
	addr_space& mem, const proc_module& mod,
	unwind_context& ctx, unwind_result& result)
{
	const auto func = lookup_function_entry(mod, ctx.pc);

	if (!func)
	{
		result = {};
		result.establisher_frame = ctx.sp;
		ctx.pc = mem.read_mem<addr_t>(ctx.sp);
		ctx.sp += sizeof(std::uint64_t);
		return ctx.pc != 0;
	}

	result = apply_unwind_info(mem, mod, *func, ctx);
	return ctx.pc != 0;
}

addr_t x64_unwinder::ensure_trampoline(vcpu& cpu)
{
	std::call_once(trampoline_once_, [&]
	{
		auto& space = *cpu.curr_addr_space();
		trampoline_ = space.alloc(0x1000, prot_rwx);

		cpu.emu()->hook_code(trampoline_, trampoline_,
			[](vcpu& c, addr_t, std::size_t) { c.stop(); });
	});

	return trampoline_;
}

std::int32_t x64_unwinder::call_filter(
	vcpu& cpu, addr_t filter_addr, addr_t establisher_frame,
	const exception_info& info)
{
	auto& space = *cpu.curr_addr_space();
	const auto trampoline = ensure_trampoline(cpu);

	const auto saved_rcx = cpu.reg(x86::rcx);
	const auto saved_rdx = cpu.reg(x86::rdx);
	const auto saved_rsp = cpu.sp();
	const auto saved_rip = cpu.pc();

	exception_record64 record{};
	record.exception_code = info.code;
	record.exception_address = info.exception_address;
	if (info.code == status_access_violation)
	{
		record.number_parameters = 2;
		record.exception_information[0] = 0;
		record.exception_information[1] = info.fault_address;
	}

	context64 ctx{};
	ctx.context_flags = 0x10000F;
	ctx.rax = cpu.reg(x86::rax);
	ctx.rcx = cpu.reg(x86::rcx);
	ctx.rdx = cpu.reg(x86::rdx);
	ctx.rbx = cpu.reg(x86::rbx);
	ctx.rsp = cpu.sp();
	ctx.rbp = cpu.reg(x86::rbp);
	ctx.rsi = cpu.reg(x86::rsi);
	ctx.rdi = cpu.reg(x86::rdi);
	ctx.r8  = cpu.reg(x86::r8);
	ctx.r9  = cpu.reg(x86::r9);
	ctx.r10 = cpu.reg(x86::r10);
	ctx.r11 = cpu.reg(x86::r11);
	ctx.r12 = cpu.reg(x86::r12);
	ctx.r13 = cpu.reg(x86::r13);
	ctx.r14 = cpu.reg(x86::r14);
	ctx.r15 = cpu.reg(x86::r15);
	ctx.rip = info.exception_address;

	constexpr std::size_t filter_stack_size = 0x4000;
	const auto alloc_base = space.alloc(filter_stack_size, prot_rw);

	constexpr std::size_t data_offset = 0x100;
	const auto record_addr = alloc_base + data_offset;
	const auto ctx_addr = (record_addr + sizeof(exception_record64) + 0xF) & ~addr_t(0xF);
	const auto ptrs_addr = ctx_addr + sizeof(context64);

	space.write_mem(record_addr, record);
	space.write_mem(ctx_addr, ctx);

	const std::uint64_t ptrs[2] = { record_addr, ctx_addr };
	space.write_mem(ptrs_addr, &ptrs, sizeof(ptrs));

	auto filter_rsp = ((alloc_base + filter_stack_size) & ~addr_t(0xF)) - 0x28;
	filter_rsp -= 8;
	space.write_mem(filter_rsp, trampoline);

	cpu.reg(x86::rcx, ptrs_addr);
	cpu.reg(x86::rdx, establisher_frame);
	cpu.set_sp(filter_rsp);
	cpu.set_pc(filter_addr);

	cpu.run();

	const auto result = static_cast<std::int32_t>(cpu.reg(x86::rax));

	cpu.reg(x86::rcx, saved_rcx);
	cpu.reg(x86::rdx, saved_rdx);
	cpu.set_sp(saved_rsp);
	cpu.set_pc(saved_rip);

	return result;
}

handler_result x64_unwinder::evaluate_handler(
	vcpu& cpu, const proc_module& mod, const unwind_result& result,
	addr_t control_pc, const exception_info& info)
{
	const auto* img = mod.pe();
	if (!img)
		return { exception_continue_search, 0, 0 };

	const auto* img_base = img->as<const std::uint8_t*>();
	const auto data_rva = static_cast<std::uint32_t>(result.handler_data - mod.addr);
	const auto* scope_table = reinterpret_cast<const std::uint32_t*>(img_base + data_rva);
	const auto scope_count = scope_table[0];
	const auto* scopes = reinterpret_cast<const scope_entry*>(&scope_table[1]);
	const auto pc_rva = static_cast<std::uint32_t>(control_pc - mod.addr);

	for (std::uint32_t i = 0; i < scope_count; ++i)
	{
		const auto& scope = scopes[i];

		if (pc_rva < scope.begin_address || pc_rva >= scope.end_address)
			continue;

		if (!scope.jump_target)
			continue;

		if (scope.handler_address == 1)
		{
			const auto target = mod.addr + scope.jump_target;
			LOG_INFO("  EXCEPTION_EXECUTE_HANDLER -> 0x{:X}", target);
			return { exception_execute_handler, target, result.establisher_frame };
		}

		const auto filter_addr = mod.addr + scope.handler_address;
		LOG_INFO("  calling filter at 0x{:X}", filter_addr);

		const auto filter_result = call_filter(cpu, filter_addr, result.establisher_frame, info);
		LOG_INFO("  filter returned {}", filter_result);

		if (filter_result < 0)
			return { exception_continue_execution, 0, 0 };

		if (filter_result > 0)
		{
			const auto target = mod.addr + scope.jump_target;
			return { exception_execute_handler, target, result.establisher_frame };
		}
	}

	return { exception_continue_search, 0, 0 };
}

} // namespace win

#endif // KERNEMUL_ARCH_X64
