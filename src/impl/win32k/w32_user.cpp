#include "w32_helpers.hpp"

void redirect_win32k_user_functions(const std::shared_ptr<emulator_t>& emulator, const image_t& mapped_image)
{
	redirect_function(
		kernel::function_implementation_t([emulator](bool&)
		{
			const auto hwnd = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto text_ptr = emulator->read_register<x86::reg::rdx, std::uint64_t>();
			const auto caption_ptr = emulator->read_register<x86::reg::r8, std::uint64_t>();
			const auto type = emulator->read_register<x86::reg::r9, std::uint32_t>();

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

			emulator->write_register<x86::reg::rax>(static_cast<std::uint64_t>(1));
		}),
		mapped_image,
		"NtUserMessageCall"
	);
}
