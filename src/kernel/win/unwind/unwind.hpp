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
};

struct unwind_result
{
	addr_t handler;
	addr_t handler_data;
};

struct stack_frame
{
	addr_t pc;
	addr_t sp;
};

struct win_unwinder
{
	virtual ~win_unwinder() = default;

	virtual unwind_context context_from_vcpu(vcpu& cpu) = 0;
	virtual bool unwind_frame(addr_space& mem, const proc_module& mod, unwind_context& ctx, unwind_result& result) = 0;
};

std::unique_ptr<win_unwinder> make_unwinder(const proc_module& mod);

std::vector<stack_frame> walk_stack(
	win_unwinder& unwinder, addr_space& mem, const process& proc,
	unwind_context ctx, std::size_t max_frames = 64);

} // namespace win
