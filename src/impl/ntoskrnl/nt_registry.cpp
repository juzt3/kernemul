#include "nt_helpers.hpp"

void redirect_ntoskrnl_registry_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			const auto r9 = emulator->read_register<x86::reg::r9, std::uint64_t>();

			spdlog::info("RtlWriteRegistryValue called with type: 0x{:X}", r9);

			write_nt_success(emulator);
		},
		mapped_image,
		"RtlWriteRegistryValue"
	);

	redirect_function(
		[emulator]
		{
			spdlog::info("RtlDeleteRegistryValue called");

			write_nt_success(emulator);
		},
		mapped_image,
		"RtlDeleteRegistryValue"
	);

	redirect_function(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rdx = emulator->read_register<x86::reg::rdx, std::uint32_t>();

			spdlog::info("ZwOpenKey called (desired access=0x{:X})", rdx);

			write_dummy_handle(emulator, rcx);

			write_nt_success(emulator);
		},
		mapped_image,
		"ZwOpenKey"
	);

	redirect_function(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();

			spdlog::info("ZwFlushKey called (key handle=0x{:X})", rcx);

			write_nt_success(emulator);
		},
		mapped_image,
		"ZwFlushKey"
	);

	redirect_function(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();

			spdlog::info("ZwClose called (handle=0x{:X})", rcx);

			write_nt_success(emulator);
		},
		mapped_image,
		"ZwClose"
	);
}
