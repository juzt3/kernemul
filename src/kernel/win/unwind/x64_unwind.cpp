#include "x64_unwind.hpp"
#include "../../process.hpp"
#include "../../../emu/emu.hpp"
#include "../../../emu/x86/arch.hpp"

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

static std::size_t slots_for_code(pe::unwind_opcode_x64 op, std::uint8_t info)
{
	switch (op)
	{
	case push_nonvol:
	case alloc_small:
	case set_fpreg:
	case push_machframe:
		return 1;
	case save_nonvol:
	case epilog:
	case save_xmm128:
		return 2;
	case alloc_large:
		return info == 0 ? 2 : 3;
	case save_nonvol_far:
	case spare:
	case save_xmm128_far:
		return 3;
	default:
		return 1;
	}
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
			const auto n = slots_for_code(op, reg);

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

} // namespace win
