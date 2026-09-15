#pragma once
#include "unwind.hpp"
#include <pe.hpp>
#include <optional>

namespace win {

// runtime_function_arm64 records a length, not an end address; where it lives depends on packing.
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

	static std::optional<arm64_function_entry> lookup_function_entry(
		const proc_module& mod, addr_t pc);
};

} // namespace win
