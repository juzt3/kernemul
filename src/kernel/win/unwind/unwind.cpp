#include "unwind.hpp"
#include "x64_unwind.hpp"
#include "../../process.hpp"

namespace win {

std::unique_ptr<win_unwinder> make_unwinder(const proc_module& mod)
{
	const auto* img = mod.pe();
	if (!img)
		return nullptr;

	if (img->is_x64())
		return std::make_unique<x64_unwinder>();

	return nullptr;
}

std::vector<stack_frame> walk_stack(
	win_unwinder& unwinder, addr_space& mem, const process& proc,
	unwind_context ctx, const std::size_t max_frames)
{
	std::vector<stack_frame> frames;
	frames.push_back({ ctx.pc, ctx.sp });

	for (std::size_t i = 0; i < max_frames; ++i)
	{
		const auto mod = proc.find_module_by_addr(ctx.pc);
		if (!mod)
			break;

		unwind_result result{};
		if (!unwinder.unwind_frame(mem, *mod, ctx, result))
			break;

		frames.push_back({ ctx.pc, ctx.sp });
	}

	return frames;
}

} // namespace win
