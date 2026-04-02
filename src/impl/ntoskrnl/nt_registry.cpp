#include "nt_helpers.hpp"

void redirect_ntoskrnl_registry_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			const auto r9 = emulator->read_register<x86::reg::r9, std::uint64_t>();

			THREAD_LOG("RtlWriteRegistryValue called with type: 0x{:X}", r9);

			write_nt_success(emulator);
		},
		mapped_image,
		"RtlWriteRegistryValue"
	);

	redirect_function(
		[emulator]
		{
			THREAD_LOG("RtlDeleteRegistryValue called");

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

			THREAD_LOG("ZwOpenKey called (desired access=0x{:X})", rdx);

			auto host_object = std::make_shared<registry_key_object_t>();

			constexpr std::size_t registry_key_body_size = 8;
			std::array<std::uint8_t, registry_key_body_size> body{};
			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size(), host_object);
			const auto handle_value = kernel::object_manager->create_handle(body_address, rdx);

			emulator_err_t error = emulator->write_virtual_memory(rcx, &handle_value, sizeof(handle_value));
			error.throw_if("ZwOpenKey: write handle");

			write_nt_success(emulator);
		},
		mapped_image,
		"ZwOpenKey"
	);

	redirect_function(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();

			THREAD_LOG("ZwFlushKey called (key handle=0x{:X})", rcx);

			write_nt_success(emulator);
		},
		mapped_image,
		"ZwFlushKey"
	);

	const auto query_value_key_handler = [emulator](const std::string_view caller_name)
	{
		const auto key_handle = emulator->read_register<x86::reg::rcx, std::uint64_t>();
		const auto value_name_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
		const auto info_class = emulator->read_register<x86::reg::r8, std::uint32_t>();
		const auto info_buffer = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

		const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

		std::uint32_t length = 0;
		emulator_t::address_type result_length_address = 0;
		static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &length, sizeof(length)));
		static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &result_length_address, sizeof(result_length_address)));

		std::string value_name_string;

		if (value_name_address)
		{
			UNICODE_STRING unicode_string{};
			static_cast<void>(emulator->read_virtual_memory(value_name_address, &unicode_string, sizeof(unicode_string)));

			const auto buffer_address = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

			if (buffer_address && unicode_string.Length)
			{
				value_name_string = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
			}
		}

		THREAD_LOG("{} called (handle=0x{:X}, value='{}', class={}, buffer=0x{:X}, length={}, result_length=0x{:X})",
			caller_name, key_handle, value_name_string, info_class, info_buffer, length, result_length_address);

		if (result_length_address)
		{
			const std::uint32_t zero = 0;
			static_cast<void>(emulator->write_virtual_memory(result_length_address, &zero, sizeof(zero)));
		}

		constexpr std::uint32_t status_object_name_not_found = 0xC0000034;
		write_nt_status(emulator, status_object_name_not_found);
	};

	redirect_function(
		[query_value_key_handler] { query_value_key_handler("NtQueryValueKey"); },
		mapped_image, "NtQueryValueKey"
	);

	redirect_function(
		[query_value_key_handler] { query_value_key_handler("ZwQueryValueKey"); },
		mapped_image, "ZwQueryValueKey"
	);

	// todo: actually register registry callback
	redirect_function(
		[emulator]
		{
			const auto function = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto altitude_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto driver = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto context = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
			emulator_t::address_type cookie_address = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &cookie_address, sizeof(cookie_address)));

			std::string altitude_string;

			if (altitude_address)
			{
				UNICODE_STRING unicode_string = { };
				static_cast<void>(emulator->read_virtual_memory(altitude_address, &unicode_string, sizeof(unicode_string)));

				const auto buffer_address = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

				if (buffer_address && unicode_string.Length)
				{
					altitude_string = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
				}
			}

			THREAD_LOG("CmRegisterCallbackEx called (function=0x{:X}, altitude='{}', driver=0x{:X}, context=0x{:X}, cookie=0x{:X})",
				function, altitude_string, driver, context, cookie_address);

			if (cookie_address)
			{
				constexpr std::uint64_t dummy_cookie = 1;
				static_cast<void>(emulator->write_virtual_memory(cookie_address, &dummy_cookie, sizeof(dummy_cookie)));
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"CmRegisterCallbackEx"
	);
}
