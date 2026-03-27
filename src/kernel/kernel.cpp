#include "kernel.hpp"
#include "../util/logs.hpp"

std::shared_ptr<kernel_image_t> kernel::find_module(const std::string_view name)
{
	const auto it = std::ranges::find(module_entries, name, &kernel_image_t::name);

	return it != std::ranges::end(module_entries) ? *it : nullptr;
}

std::shared_ptr<kernel_image_t> kernel::find_module_from_rip(const emulator_t::address_type rip)
{
	const auto it = std::ranges::find_if(module_entries,
		[rip](const std::shared_ptr<kernel_image_t>& image) -> bool
		{
			const emulator_t::address_type start = image->base_address();
			const emulator_t::address_type end = start + image->size();

			return start <= rip && rip < end;
		}
	);

	return it != std::ranges::end(module_entries) ? *it : nullptr;
}

thread_t::id_type kernel::current_thread_id()
{
	return current_thread->id();
}

std::optional<kernel::function_implementation_t> kernel::find_redirected_function(const emulator_t::address_type address)
{
	const auto it = redirected_functions.find(address);

	if (it != std::ranges::end(redirected_functions))
	{
		return it->second;
	}

	return std::nullopt;
}