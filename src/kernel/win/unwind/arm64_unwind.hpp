#pragma once
#include "unwind.hpp"
#include <pe.hpp>
#include <optional>

namespace win {

// A .pdata entry plus the function extent, which on AArch64 has to be derived:
// runtime_function_arm64 records a length rather than an end address, and where
// that length lives depends on whether the entry is packed.
struct arm64_function_entry
{
	std::uint32_t begin_rva;
	std::uint32_t length;       // in bytes
	std::uint32_t unwind_data;  // packed word, or the .xdata RVA
	bool packed;
};

struct arm64_unwinder final : win_unwinder
{
	unwind_context context_from_vcpu(vcpu& cpu) override;
	bool unwind_frame(addr_space& mem, const proc_module& mod, unwind_context& ctx, unwind_result& result) override;
	handler_result evaluate_handler(vcpu& cpu, const proc_module& mod, const unwind_result& result, addr_t control_pc, const exception_info& info) override;

	static std::optional<arm64_function_entry> lookup_function_entry(
		const proc_module& mod, addr_t pc);

private:
	std::int32_t call_filter(vcpu& cpu, addr_t filter_addr, addr_t establisher_frame, const exception_info& info);
	addr_t ensure_trampoline(vcpu& cpu);

	// Allocated on the first filter call, from whichever cpu makes it.
	std::once_flag trampoline_once_;
	addr_t trampoline_ = 0;
};

} // namespace win
