#pragma once
#include "unwind.hpp"
#include <pe.hpp>
#include <optional>

namespace win {

struct x64_unwinder final : win_unwinder
{
	unwind_context context_from_vcpu(vcpu& cpu) override;
	bool unwind_frame(addr_space& mem, const proc_module& mod, unwind_context& ctx, unwind_result& result) override;

	static std::optional<pe::runtime_function_x64> lookup_function_entry(
		const proc_module& mod, addr_t rip);
};

} // namespace win
