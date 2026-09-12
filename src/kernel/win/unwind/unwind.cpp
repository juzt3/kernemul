#include "unwind.hpp"
#include "../../../target.hpp"
#include "../../../util/log.hpp"

#if defined(KERNEMUL_ARCH_ARM64)
	#include "arm64_unwind.hpp"
#else
	#include "x64_unwind.hpp"
#endif
#include "../../process.hpp"

namespace win {

std::unique_ptr<win_unwinder> make_unwinder(const proc_module& mod)
{
	const auto* img = mod.pe();
	if (!img)
		return nullptr;

#if defined(KERNEMUL_ARCH_ARM64)
	if (img->is_arm64())
		return std::make_unique<arm64_unwinder>();
#else
	if (img->is_x64())
		return std::make_unique<x64_unwinder>();
#endif

	LOG_ERR("{} was built for another architecture than this emulator", mod.name);
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
