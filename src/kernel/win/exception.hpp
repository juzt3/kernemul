#pragma once
#include "../kernel.hpp"
#include "unwind/unwind.hpp"
#include <mutex>

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

struct exception_record64
{
	std::uint32_t exception_code;
	std::uint32_t exception_flags;
	std::uint64_t exception_record;
	std::uint64_t exception_address;
	std::uint32_t number_parameters;
	std::uint32_t __unused_alignment;
	std::uint64_t exception_information[15];
};

static_assert(sizeof(exception_record64) == 152);

struct alignas(16) context64
{
	std::uint64_t p_home[6];
	std::uint32_t context_flags;
	std::uint32_t mx_csr;
	std::uint16_t seg_cs, seg_ds, seg_es, seg_fs, seg_gs, seg_ss;
	std::uint32_t eflags;
	std::uint64_t dr[6];
	std::uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
	std::uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
	std::uint64_t rip;
	std::uint8_t  flt_save[512];
	std::uint8_t  vector_register[26 * 16];
	std::uint64_t vector_control;
	std::uint64_t debug_control;
	std::uint64_t last_branch_to_rip;
	std::uint64_t last_branch_from_rip;
	std::uint64_t last_exception_to_rip;
	std::uint64_t last_exception_from_rip;
};

struct dispatcher_context64
{
	std::uint64_t control_pc;
	std::uint64_t image_base;
	std::uint64_t function_entry;
	std::uint64_t establisher_frame;
	std::uint64_t target_ip;
	std::uint64_t context_record;
	std::uint64_t language_handler;
	std::uint64_t handler_data;
	std::uint64_t history_table;
	std::uint32_t scope_index;
	std::uint32_t fill0;
};

constexpr std::int32_t exception_continue_execution = 0;
constexpr std::int32_t exception_continue_search     = 1;
constexpr std::int32_t exception_execute_handler      = 2;

std::uint32_t exception_to_status(cpu_exception ex);

struct win_exception final : os_exception
{
	explicit win_exception(win_kernel_state& kernel);
	bool handle(vcpu& cpu, cpu_exception ex) override;

private:
	bool handle_page_fault(vcpu& cpu);

	win_kernel_state& kernel_;

	// Built on the first fault, from whichever cpu faults first, and only read
	// afterwards -- so this is a build-once, not a reader/writer problem.
	std::once_flag unwinder_once_;
	std::unique_ptr<win_unwinder> unwinder_;
};

} // namespace win
