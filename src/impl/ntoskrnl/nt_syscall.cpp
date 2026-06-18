#include "nt_helpers.hpp"
#include "../../kernel/segments.hpp"
#include "../../user/syscall_table.hpp"

#include <ia32-doc/ia32.hpp>

constexpr std::uint32_t status_not_implemented = 0xC0000002;

void redirect_ntoskrnl_syscall_handler(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_function(
		kernel::function_implementation_t(
			[emulator](bool& skip_return)
			{
				skip_return = true;

				const auto syscall_number = emulator->read_register<x86::reg::rax, std::uint32_t>();

				// SYSCALL puts return RIP in RCX and RFLAGS in R11
				const auto return_rip = emulator->read_register<x86::reg::rcx, std::uint64_t>();
				const auto return_rflags = emulator->read_register<x86::reg::r11, std::uint64_t>();

				// ntdll does mov r10, rcx before syscall - restore rcx from r10
				const auto original_rcx = emulator->read_register<x86::reg::r10, std::uint64_t>();
				emulator->write_register<x86::reg::rcx>(original_rcx);

				// restore usermode state before dispatching (match sogen pattern)
				emulator->write_register<x86::reg::rflags>(return_rflags | 0x2);

				kernel::swap_to_usermode_segments(emulator);

				const auto entry = user::syscall_table.find_by_number(syscall_number);

				bool inner_skip = false;

				if (entry)
				{
					THREAD_LOG("syscall #{} ({}) dispatching", syscall_number, entry->name);
					entry->handler(inner_skip);

					const auto result = emulator->read_register<x86::reg::rax, std::uint32_t>();
					if (static_cast<std::int32_t>(result) < 0)
					{
						THREAD_WARN_LOG("syscall #{} ({}) returned error 0x{:08X}", syscall_number, entry->name, result);
					}
				}
				else
				{
					const auto name = user::syscall_table.find_name(syscall_number);

					if (!name.empty())
					{
						THREAD_WARN_LOG("unimplemented syscall #{} ({})", syscall_number, name);
					}
					else
					{
						THREAD_WARN_LOG("unknown syscall #{}", syscall_number);
					}

					write_nt_status(emulator, status_not_implemented);
				}

				if (!inner_skip)
				{
					emulator->write_register<x86::reg::rip>(return_rip);
				}
			}
		),
		mapped_image,
		"KiSystemCall64"
	);
}
