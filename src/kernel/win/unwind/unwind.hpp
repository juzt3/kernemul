#pragma once
#include "../../../emu/defs.hpp"
#include <cstdint>
#include <memory>
#include <vector>

struct addr_space;
struct proc_module;
class process;
class vcpu;

namespace win {

struct unwind_context
{
	addr_t pc;
	addr_t sp;
	static constexpr int max_gp = 31;
	addr_t gp[max_gp];

	// d8-d15, the callee-saved half of the FP/SIMD registers. Only the low 64
	// bits are ever spilled by a prologue, so that is all that is tracked.
	// AArch64 only; the x64 unwinder ignores its save_xmm128 codes.
	static constexpr int max_fp = 8;
	addr_t fp_regs[max_fp];
};

struct unwind_result
{
	addr_t handler;
	addr_t handler_data;
	addr_t establisher_frame;
};

struct stack_frame
{
	addr_t pc;
	addr_t sp;
};

struct exception_info
{
	std::uint32_t code;
	addr_t exception_address;
	addr_t fault_address;
};

struct handler_result
{
	std::int32_t disposition;
	addr_t target_ip;
	addr_t establisher_frame;
};

struct win_unwinder
{
	virtual ~win_unwinder() = default;

	virtual unwind_context context_from_vcpu(vcpu& cpu) = 0;
	virtual bool unwind_frame(addr_space& mem, const proc_module& mod, unwind_context& ctx, unwind_result& result) = 0;
	virtual handler_result evaluate_handler(vcpu& cpu, const proc_module& mod, const unwind_result& result, addr_t control_pc, const exception_info& info) = 0;
};

std::unique_ptr<win_unwinder> make_unwinder(const proc_module& mod);

std::vector<stack_frame> walk_stack(
	win_unwinder& unwinder, addr_space& mem, const process& proc,
	unwind_context ctx, std::size_t max_frames = 64);

} // namespace win
