#include "kernel.hpp"
#include "../user/user.hpp"
#include "../util/logs.hpp"

std::shared_ptr<image_t> kernel::find_module(const std::string_view name)
{
	const auto it = std::ranges::find(module_entries, name, &image_t::name);

	if (it != std::ranges::end(module_entries))
	{
		return *it;
	}

	const auto user_it = std::ranges::find(user::module_entries, name, &image_t::name);

	return user_it != std::ranges::end(user::module_entries) ? *user_it : nullptr;
}

std::shared_ptr<image_t> kernel::find_module_from_rip(const emulator_t::address_type rip)
{
	const auto match = [rip](const std::shared_ptr<image_t>& image) -> bool
	{
		const emulator_t::address_type start = image->base_address();
		const emulator_t::address_type end = start + image->size();

		return start <= rip && rip < end;
	};

	const auto it = std::ranges::find_if(module_entries, match);

	if (it != std::ranges::end(module_entries))
	{
		return *it;
	}

	const auto user_it = std::ranges::find_if(user::module_entries, match);

	return user_it != std::ranges::end(user::module_entries) ? *user_it : nullptr;
}

thread_t::id_type kernel::current_thread_id()
{
	return current_thread->id();
}

std::uint64_t kernel::current_process_id()
{
	return current_thread ? current_thread->process()->id() : 0;
}

const char* kernel::current_mode_string()
{
	if (current_thread && current_thread->state().is_usermode)
	{
		return "user";
	}

	return "kernel";
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