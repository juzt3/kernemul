#include "w32_helpers.hpp"

static std::uint64_t handle_user_message_call(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t hwnd, emulator_t::address_type text_ptr, emulator_t::address_type caption_ptr,
	std::uint32_t type)
{
	std::string text_str = "(null)";
	std::string caption_str = "(null)";

	if (text_ptr)
	{
		text_str = util::narrow_wstring(kernel::read_guest_wstring(*emulator, text_ptr));
	}

	if (caption_ptr)
	{
		caption_str = util::narrow_wstring(kernel::read_guest_wstring(*emulator, caption_ptr));
	}

	THREAD_LOG("MessageBox(hwnd=0x{:X}, text='{}', caption='{}', type=0x{:X})",
		hwnd, text_str, caption_str, type);

	return 1;
}

void redirect_win32k_user_functions(const std::shared_ptr<emulator_t>& emulator, const image_t& mapped_image)
{
	redirect_handler<handle_user_message_call>(emulator, mapped_image, "NtUserMessageCall");
}
