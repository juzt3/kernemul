#include "nt_helpers.hpp"

static std::uint8_t get_guest_irql(const std::shared_ptr<emulator_t>& emulator)
{
	return emulator->read_register<x86::reg::cr8, std::uint8_t>();
}

void redirect_ntoskrnl_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image, const portable_executable::image_t* const pe_image)
{
	// todo: actually register callbacks into a list and invoke on bugcheck
	redirect_image_export(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rdx = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto r8 = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto r9 = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			std::string component_name;

			if (r9)
			{
				component_name = read_guest_string(*emulator, r9);
			}

			spdlog::info("KeRegisterBugCheckReasonCallback called (record=0x{:X}, routine=0x{:X}, reason=0x{:X}, component='{}')",
				rcx, rdx, r8, component_name);

			write_return_value(emulator, 1);
		},
		pe_image,
		mapped_image,
		"KeRegisterBugCheckReasonCallback"
	);

	redirect_image_export(
		[emulator]
		{
			const auto irql = get_guest_irql(emulator);
			const bool result = irql != 0;

			spdlog::info("KeAreAllApcsDisabled called (irql={}, result={})", irql, result);

			write_return_value(emulator, result);
		},
		pe_image,
		mapped_image,
		"KeAreAllApcsDisabled"
	);

	redirect_image_export(
		[emulator]
		{
			const auto irql = get_guest_irql(emulator);

			spdlog::info("KeGetCurrentIrql called (irql={})", irql);

			write_return_value(emulator, irql);
		},
		pe_image,
		mapped_image,
		"KeGetCurrentIrql"
	);

	redirect_image_export(
		[emulator]
		{
			const auto broadcast_function = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto context = emulator->read_register<x86::reg::rdx, std::uint64_t>();

			spdlog::info("KeIpiGenericCall called (broadcast_function=0x{:X}, context=0x{:X})", broadcast_function, context);

			const auto saved_rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			constexpr std::uint64_t shadow_space_size = 0x20;
			constexpr std::uint64_t return_address_size = 8;

			auto call_rsp = saved_rsp - shadow_space_size - return_address_size;
			call_rsp &= ~0xFull;
			call_rsp -= return_address_size;

			emulator_err_t error = emulator->write_virtual_memory(
				call_rsp, &emulator_t::thread_return_address, sizeof(emulator_t::thread_return_address));

			error.throw_if("KeIpiGenericCall: write return address");

			emulator->write_register<x86::reg::rsp>(call_rsp);
			emulator->write_register<x86::reg::rcx>(context);

			spdlog::info("KeIpiGenericCall: invoking guest BroadcastFunction at 0x{:X} with context=0x{:X}", broadcast_function, context);

			error = emulator->run_at(broadcast_function, emulator_t::thread_return_address);

			error.throw_if("KeIpiGenericCall: run guest callback");

			const auto result = emulator->read_register<x86::reg::rax, std::uint64_t>();

			spdlog::info("KeIpiGenericCall: guest BroadcastFunction returned 0x{:X}", result);

			emulator->write_register<x86::reg::rsp>(saved_rsp);

			write_return_value(emulator, result);
		},
		pe_image,
		mapped_image,
		"KeIpiGenericCall"
	);
}
