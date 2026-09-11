#pragma once
#include "../kernel.hpp"
#include "unwind/unwind.hpp"

class win_kernel_state;

namespace win {

constexpr std::uint32_t status_access_violation      = 0xC0000005;
constexpr std::uint32_t status_integer_divide_by_zero = 0xC0000094;
constexpr std::uint32_t status_single_step            = 0x80000004;
constexpr std::uint32_t status_breakpoint             = 0x80000003;
constexpr std::uint32_t status_illegal_instruction    = 0xC000001D;

struct scope_entry
{
	std::uint32_t begin_address;
	std::uint32_t end_address;
	std::uint32_t handler_address;
	std::uint32_t jump_target;
};

std::uint32_t exception_to_status(cpu_exception ex);

struct win_exception final : os_exception
{
	explicit win_exception(win_kernel_state& kernel);
	bool handle(vcpu& cpu, cpu_exception ex) override;

private:
	win_kernel_state& kernel_;
	std::unique_ptr<win_unwinder> unwinder_;
};

} // namespace win
