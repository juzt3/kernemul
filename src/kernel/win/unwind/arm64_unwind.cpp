#include "../../../target.hpp"
#if defined(KERNEMUL_ARCH_ARM64)
#include "arm64_unwind.hpp"
#include "../exception.hpp"
#include "../types.hpp"
#include "../../process.hpp"
#include "../../../emu/emu.hpp"
#include "../../../emu/arm64/arch.hpp"
#include "../../../util/log.hpp"

namespace win {

namespace {

constexpr int reg_fp = 29;
constexpr int reg_lr = 30;

// ARM64_NT_CONTEXT comes from the PDB as _CONTEXT, so CONTEXT_ARM64_FULL is the
// only part that has to be spelled out here.
constexpr std::uint32_t context_arm64_full = 0x00400000 | 0x1 | 0x2 | 0x4;

struct xdata_header
{
	std::uint32_t function_length;  // bytes
	std::uint32_t epilog_count;
	std::uint32_t code_words;
	bool exception_data;
	bool epilog_in_header;
	const std::uint8_t* codes;
	const std::uint32_t* after_codes;
};

// Layout of an .xdata record: one header word, optionally an extension word
// when both counts overflow their fields, the epilog scope words, the unwind
// code words, then the exception handler RVA and its data.
std::optional<xdata_header> parse_xdata(const std::uint8_t* img_base, const std::uint32_t rva)
{
	const auto* words = reinterpret_cast<const std::uint32_t*>(img_base + rva);
	const std::uint32_t w0 = words[0];

	xdata_header h{};
	h.function_length  = (w0 & 0x3FFFF) * 4;
	h.exception_data   = (w0 >> 20) & 1;
	h.epilog_in_header = (w0 >> 21) & 1;
	h.epilog_count     = (w0 >> 22) & 0x1F;
	h.code_words       = (w0 >> 27) & 0x1F;

	const std::uint32_t version = (w0 >> 18) & 3;
	if (version != 0)
	{
		LOG_WARN("unsupported arm64 xdata version {}", version);
		return std::nullopt;
	}

	std::size_t next = 1;

	// Both zero means the real counts live in an extension word.
	if (h.epilog_count == 0 && h.code_words == 0)
	{
		const std::uint32_t w1 = words[next++];
		h.epilog_count = w1 & 0xFFFF;
		h.code_words   = (w1 >> 16) & 0xFF;
	}

	// With E set, the single epilog scope is packed into the header instead of
	// getting its own word.
	if (!h.epilog_in_header)
		next += h.epilog_count;

	h.codes = reinterpret_cast<const std::uint8_t*>(words + next);
	h.after_codes = words + next + h.code_words;
	return h;
}

// Replays the unwind codes, which describe the prologue in reverse, so running
// them in array order undoes it.
class code_replayer
{
public:
	code_replayer(addr_space& mem, unwind_context& ctx)
		: mem_(mem), ctx_(ctx) {}

	// Returns false if a code we do not model turned up, in which case the
	// context is left untrustworthy and the caller should give up.
	bool run(const std::uint8_t* codes, const std::size_t size)
	{
		for (std::size_t i = 0; i < size; )
		{
			const std::uint8_t b0 = codes[i];
			const auto b1 = [&]() -> std::uint8_t { return i + 1 < size ? codes[i + 1] : 0; };

			if ((b0 & 0xE0) == 0x00)            // alloc_s  000xxxxx
			{
				ctx_.sp += (b0 & 0x1F) * 16ull;
				i += 1;
			}
			else if ((b0 & 0xE0) == 0x20)       // save_r19r20_x  001zzzzz
			{
				load_pair(19, 0);
				ctx_.sp += (b0 & 0x1F) * 8ull;
				i += 1;
			}
			else if ((b0 & 0xC0) == 0x40)       // save_fplr  01zzzzzz
			{
				load_pair(reg_fp, (b0 & 0x3F) * 8ull);
				i += 1;
			}
			else if ((b0 & 0xC0) == 0x80)       // save_fplr_x  10zzzzzz
			{
				load_pair(reg_fp, 0);
				ctx_.sp += ((b0 & 0x3F) + 1) * 8ull;
				i += 1;
			}
			else if ((b0 & 0xF8) == 0xC0)       // alloc_m  11000xxx xxxxxxxx
			{
				ctx_.sp += ((((b0 & 0x07) << 8) | b1()) * 16ull);
				i += 2;
			}
			else if ((b0 & 0xFC) == 0xC8)       // save_regp  110010xx xxzzzzzz
			{
				const int x = ((b0 & 0x03) << 2) | (b1() >> 6);
				mark_pair(19 + x, (b1() & 0x3F) * 8ull, false);
				load_pair(19 + x, (b1() & 0x3F) * 8ull);
				i += 2;
			}
			else if ((b0 & 0xFC) == 0xCC)       // save_regp_x  110011xx xxzzzzzz
			{
				const int x = ((b0 & 0x03) << 2) | (b1() >> 6);
				mark_pair(19 + x, 0, false);
				load_pair(19 + x, 0);
				ctx_.sp += ((b1() & 0x3F) + 1) * 8ull;
				i += 2;
			}
			else if ((b0 & 0xFC) == 0xD0)       // save_reg  110100xx xxzzzzzz
			{
				const int x = ((b0 & 0x03) << 2) | (b1() >> 6);
				load_reg(19 + x, (b1() & 0x3F) * 8ull);
				i += 2;
			}
			else if ((b0 & 0xFE) == 0xD4)       // save_reg_x  1101010x xxxzzzzz
			{
				const int x = ((b0 & 0x01) << 3) | (b1() >> 5);
				load_reg(19 + x, 0);
				ctx_.sp += ((b1() & 0x1F) + 1) * 8ull;
				i += 2;
			}
			else if ((b0 & 0xFE) == 0xD6)       // save_lrpair  1101011x xxzzzzzz
			{
				const int x = ((b0 & 0x01) << 2) | (b1() >> 6);
				const auto off = (b1() & 0x3F) * 8ull;
				load_reg(19 + 2 * x, off);
				load_reg(reg_lr, off + 8);
				i += 2;
			}
			else if ((b0 & 0xFE) == 0xD8        // save_fregp    1101100x
			      || (b0 & 0xFE) == 0xDC)       // save_freg     1101110x
			{
				// d8-d15 are not modelled in unwind_context; only sp matters
				// and these forms do not change it.
				mark_pair(0, 0, true);
				i += 2;
			}
			else if ((b0 & 0xFE) == 0xDA)       // save_fregp_x  1101101x xxzzzzzz
			{
				ctx_.sp += ((b1() & 0x3F) + 1) * 8ull;
				mark_pair(0, 0, true);
				i += 2;
			}
			else if (b0 == 0xDE)                // save_freg_x  11011110 xxxzzzzz
			{
				ctx_.sp += ((b1() & 0x1F) + 1) * 8ull;
				i += 2;
			}
			else if (b0 == 0xE0)                // alloc_l  11100000 + 24-bit BE
			{
				const std::uint64_t x =
					(static_cast<std::uint64_t>(codes[i + 1]) << 16) |
					(static_cast<std::uint64_t>(codes[i + 2]) << 8) |
					 static_cast<std::uint64_t>(codes[i + 3]);
				ctx_.sp += x * 16ull;
				i += 4;
			}
			else if (b0 == 0xE1)                // set_fp: mov x29, sp
			{
				ctx_.sp = ctx_.gp[reg_fp];
				i += 1;
			}
			else if (b0 == 0xE2)                // add_fp: add x29, sp, #x*8
			{
				ctx_.sp = ctx_.gp[reg_fp] - b1() * 8ull;
				i += 2;
			}
			else if (b0 == 0xE3)                // nop
			{
				i += 1;
			}
			else if (b0 == 0xE4 || b0 == 0xE5)  // end / end_c
			{
				return true;
			}
			else if (b0 == 0xE6)                // save_next
			{
				if (!last_pair_fp_)
				{
					last_pair_reg_ += 2;
					last_pair_off_ += 16;
					load_pair(last_pair_reg_, last_pair_off_);
				}
				i += 1;
			}
			else if (b0 == 0xFC)                // pac_sign_lr
			{
				// The return address was signed with PACIBSP. Nothing to undo
				// here: Unicorn runs without pointer authentication, so the
				// value on the stack is unsigned.
				i += 1;
			}
			else
			{
				LOG_WARN("unhandled arm64 unwind opcode 0x{:02X}", b0);
				return false;
			}
		}

		return true;
	}

private:
	void load_reg(const int reg, const std::uint64_t off)
	{
		if (reg < unwind_context::max_gp)
			ctx_.gp[reg] = mem_.read_mem<addr_t>(ctx_.sp + off);
	}

	void load_pair(const int reg, const std::uint64_t off)
	{
		load_reg(reg, off);
		load_reg(reg == reg_fp ? reg_lr : reg + 1, off + 8);
	}

	void mark_pair(const int reg, const std::uint64_t off, const bool is_fp)
	{
		last_pair_reg_ = reg;
		last_pair_off_ = off;
		last_pair_fp_ = is_fp;
	}

	addr_space& mem_;
	unwind_context& ctx_;

	int last_pair_reg_ = 19;
	std::uint64_t last_pair_off_ = 0;
	bool last_pair_fp_ = false;
};

// Packed .pdata carries no exception handler, so this only ever runs while
// walking through an intermediate frame -- the tested path goes through xdata.
bool apply_packed(addr_space& mem, const std::uint32_t packed, unwind_context& ctx)
{
	const std::uint32_t reg_f      = (packed >> 13) & 0x07;
	const std::uint32_t reg_i      = (packed >> 16) & 0x0F;
	const std::uint32_t h          = (packed >> 20) & 0x01;
	const std::uint32_t cr         = (packed >> 21) & 0x03;
	const std::uint64_t frame_size = ((packed >> 23) & 0x1FF) * 16ull;

	if (cr == 3)
	{
		// Chained: the {x29, lr} pair sits at the bottom of the frame.
		ctx.gp[reg_fp] = mem.read_mem<addr_t>(ctx.sp);
		ctx.gp[reg_lr] = mem.read_mem<addr_t>(ctx.sp + 8);
		ctx.sp += frame_size;
		return true;
	}

	// Unchained. The callee-saved area sits at the top of the frame, with the
	// home parameter block (when H is set) above it and LR just below that.
	const std::uint64_t home = h ? 64ull : 0ull;

	if (cr == 1 || cr == 2)
		ctx.gp[reg_lr] = mem.read_mem<addr_t>(ctx.sp + frame_size - home - 8);

	std::uint64_t off = frame_size - home - ((cr == 1 || cr == 2) ? 8 : 0) - reg_i * 8ull;
	for (std::uint32_t n = 0; n < reg_i; ++n, off += 8)
		ctx.gp[19 + n] = mem.read_mem<addr_t>(ctx.sp + off);

	(void)reg_f; // d8-d15 are not modelled in unwind_context

	ctx.sp += frame_size;

	// cr == 0 means LR was never spilled, so whatever is in x30 is still the
	// return address.
	return true;
}

} // namespace

unwind_context arm64_unwinder::context_from_vcpu(vcpu& cpu)
{
	unwind_context ctx{};
	ctx.pc = cpu.pc();
	ctx.sp = cpu.sp();

	for (int i = 0; i < 31; ++i)
		ctx.gp[i] = cpu.reg(arm64::x0 + i);

	return ctx;
}

std::optional<arm64_function_entry> arm64_unwinder::lookup_function_entry(
	const proc_module& mod, const addr_t pc)
{
	const auto* img = mod.pe();
	if (!img)
		return std::nullopt;

	const auto& exc = img->nt_hdrs()->optional_hdr.data_dirs.exception;
	if (!exc.used())
		return std::nullopt;

	const auto* base = img->as<const std::uint8_t*>();
	const auto* funcs = reinterpret_cast<const pe::runtime_function_arm64*>(base + exc.virtual_address);
	const std::uint32_t count = exc.size / sizeof(pe::runtime_function_arm64);
	const auto rva = static_cast<std::uint32_t>(pc - mod.addr);

	// Entries record a length rather than an end, so find the last one that
	// starts at or before rva and then range check it.
	std::uint32_t lo = 0, hi = count;

	while (lo < hi)
	{
		const auto mid = lo + (hi - lo) / 2;
		if (funcs[mid].begin_address <= rva)
			lo = mid + 1;
		else
			hi = mid;
	}

	if (lo == 0)
		return std::nullopt;

	const auto& entry = funcs[lo - 1];

	arm64_function_entry out{};
	out.begin_rva = entry.begin_address;
	out.unwind_data = entry.unwind_data;

	// Flag is the low two bits: 0 selects .xdata, 1 and 2 are packed forms.
	// pe::runtime_function_arm64::is_packed only looks at bit 0, which would
	// misread flag 2, so decode it here.
	const std::uint32_t flag = entry.unwind_data & 3;
	out.packed = flag != 0;

	if (out.packed)
	{
		out.length = ((entry.unwind_data >> 2) & 0x7FF) * 4;
	}
	else
	{
		const auto* words = reinterpret_cast<const std::uint32_t*>(base + entry.unwind_data);
		out.length = (words[0] & 0x3FFFF) * 4;
	}

	if (rva >= out.begin_rva + out.length)
		return std::nullopt;

	return out;
}

bool arm64_unwinder::unwind_frame(
	addr_space& mem, const proc_module& mod,
	unwind_context& ctx, unwind_result& result)
{
	result = {};

	const auto func = lookup_function_entry(mod, ctx.pc);

	if (!func)
	{
		// No unwind data: treat it as a leaf and return through the link
		// register, which is all that can be said without a frame description.
		result.establisher_frame = ctx.sp;
		ctx.pc = ctx.gp[reg_lr];
		return ctx.pc != 0;
	}

	result.establisher_frame = ctx.sp;

	if (func->packed)
	{
		if (!apply_packed(mem, func->unwind_data, ctx))
			return false;

		ctx.pc = ctx.gp[reg_lr];
		return ctx.pc != 0;
	}

	const auto* img_base = mod.pe()->as<const std::uint8_t*>();
	const auto hdr = parse_xdata(img_base, func->unwind_data);

	if (!hdr)
		return false;

	// Unwinding from the body of the function, so the whole prologue has to be
	// undone. A pc inside an epilog scope would need to start partway through
	// the codes at that scope's index instead.
	code_replayer replayer(mem, ctx);
	if (!replayer.run(hdr->codes, hdr->code_words * 4))
		return false;

	if (hdr->exception_data)
	{
		const std::uint32_t handler_rva = hdr->after_codes[0];
		result.handler = mod.addr + handler_rva;
		result.handler_data = mod.addr +
			static_cast<addr_t>(reinterpret_cast<const std::uint8_t*>(hdr->after_codes + 1) - img_base);
	}

	ctx.pc = ctx.gp[reg_lr];
	return ctx.pc != 0;
}

addr_t arm64_unwinder::ensure_trampoline(vcpu& cpu)
{
	if (trampoline_)
		return trampoline_;

	auto& space = *cpu.curr_addr_space();
	trampoline_ = space.alloc(0x1000, prot_rwx);

	cpu.emu()->hook_code(trampoline_, trampoline_,
		[](vcpu& c, addr_t, std::size_t) { c.stop(); });

	return trampoline_;
}

std::int32_t arm64_unwinder::call_filter(
	vcpu& cpu, const addr_t filter_addr, const addr_t establisher_frame,
	const exception_info& info)
{
	auto& space = *cpu.curr_addr_space();
	const auto trampoline = ensure_trampoline(cpu);

	const auto saved_x0 = cpu.reg(arm64::x0);
	const auto saved_x1 = cpu.reg(arm64::x1);
	const auto saved_lr = cpu.reg(arm64::lr);
	const auto saved_sp = cpu.sp();
	const auto saved_pc = cpu.pc();

	exception_record64 record{};
	record.exception_code = info.code;
	record.exception_address = info.exception_address;
	if (info.code == status_access_violation)
	{
		record.number_parameters = 2;
		record.exception_information[0] = 0;
		record.exception_information[1] = info.fault_address;
	}

	_CONTEXT ctx{};
	ctx.ContextFlags = context_arm64_full;
	for (int i = 0; i < 31; ++i)
		ctx.X[i] = cpu.reg(arm64::x0 + i);
	ctx.Sp = cpu.sp();
	ctx.Pc = info.exception_address;
	ctx.Cpsr = static_cast<unsigned long>(cpu.reg(arm64::pstate));

	constexpr std::size_t filter_stack_size = 0x4000;
	const auto alloc_base = space.alloc(filter_stack_size, prot_rw);

	constexpr std::size_t data_offset = 0x100;
	const auto record_addr = alloc_base + data_offset;
	const auto ctx_addr = (record_addr + sizeof(exception_record64) + 0xF) & ~addr_t(0xF);
	const auto ptrs_addr = ctx_addr + sizeof(_CONTEXT);

	space.write_mem(record_addr, record);
	space.write_mem(ctx_addr, ctx);

	const std::uint64_t ptrs[2] = { record_addr, ctx_addr };
	space.write_mem(ptrs_addr, &ptrs, sizeof(ptrs));

	// AAPCS64: sp stays 16-byte aligned, there is no home space to reserve,
	// and the return address goes in the link register rather than on the
	// stack -- which is the whole difference from the x64 path.
	const auto filter_sp = (alloc_base + filter_stack_size) & ~addr_t(0xF);

	cpu.reg(arm64::x0, ptrs_addr);
	cpu.reg(arm64::x1, establisher_frame);
	cpu.reg(arm64::lr, trampoline);
	cpu.set_sp(filter_sp);
	cpu.set_pc(filter_addr);

	cpu.run();

	const auto result = static_cast<std::int32_t>(cpu.reg(arm64::x0));

	cpu.reg(arm64::x0, saved_x0);
	cpu.reg(arm64::x1, saved_x1);
	cpu.reg(arm64::lr, saved_lr);
	cpu.set_sp(saved_sp);
	cpu.set_pc(saved_pc);

	return result;
}

handler_result arm64_unwinder::evaluate_handler(
	vcpu& cpu, const proc_module& mod, const unwind_result& result,
	const addr_t control_pc, const exception_info& info)
{
	const auto* img = mod.pe();
	if (!img)
		return { exception_continue_search, 0, 0 };

	// The C scope table __C_specific_handler walks is the same shape on both
	// architectures.
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

#endif // KERNEMUL_ARCH_ARM64
