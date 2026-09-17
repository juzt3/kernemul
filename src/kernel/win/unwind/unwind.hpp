#pragma once
#include "../../../emu/defs.hpp"
#include "../../../emu/guest_call.hpp"
#include <cstdint>
#include <memory>
#include <vector>

struct addr_space;
struct proc_module;
class process;
class vcpu;
class windows_emulator;

namespace win {

struct unwind_context
{
	addr_t pc;
	addr_t sp;
	static constexpr int max_gp = 31;
	addr_t gp[max_gp];

	// Only the low 64 bits of d8-d15 are ever spilled, so that is all that is tracked.
	static constexpr int max_fp = 8;
	addr_t fp_regs[max_fp];
};

struct unwind_result
{
	addr_t handler;
	addr_t handler_data;
	addr_t establisher_frame;
	addr_t function_entry;
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

// Not in the generated types: the kernel never stores one, it only reads them out of .xdata.
// Not in the generated types: the kernel only ever reads these out of .xdata.
struct scope_entry
{
	std::uint32_t begin_address;
	std::uint32_t end_address;
	std::uint32_t handler_address;
	std::uint32_t jump_target;
};

struct scope_search
{
	addr_t image_base = 0;
	addr_t handler_data = 0;
	addr_t control_pc = 0;
	addr_t establisher_frame = 0;
	addr_t exception_pointers = 0;
	std::size_t scratch = 0;
	std::uint32_t first_scope = 0;
};

handler_result search_scope_table(vcpu& cpu, guest_caller& calls, const scope_search& search);

struct filter_pointers
{
	addr_t address;
	std::size_t scratch;
};

filter_pointers build_exception_pointers(vcpu& cpu, windows_emulator& emulator,
	const exception_info& info);

struct dispatch_frame
{
	addr_t record = 0;
	addr_t context = 0;
	addr_t dispatcher = 0;
	std::size_t scratch = 0;
};

dispatch_frame build_dispatch_frame(vcpu& cpu, windows_emulator& emulator,
	const exception_info& info);

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
