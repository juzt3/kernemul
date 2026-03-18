#include "nt_helpers.hpp"

void redirect_ntoskrnl_object_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	// todo: actually delete the symbolic link from the object namespace
	redirect_function(
		[emulator]
		{
			const auto name_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			std::string link_name;

			if (name_address)
			{
				const auto unicode_string = emulator_object_t<UNICODE_STRING>::view_at(emulator, name_address).read();
				const auto buffer_address = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

				if (buffer_address && unicode_string.Length)
				{
					link_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
				}
			}

			spdlog::info("IoDeleteSymbolicLink called (name='{}')", link_name);

			write_nt_success(emulator);
		},
		mapped_image,
		"IoDeleteSymbolicLink"
	);

	// todo: actually open section object
	redirect_function(
		[emulator]
		{
			const auto handle_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto object_attributes_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			std::string section_name;

			if (object_attributes_address)
			{
				OBJECT_ATTRIBUTES object_attributes = { };
				emulator_err_t error = emulator->read_virtual_memory(object_attributes_address, &object_attributes, sizeof(object_attributes));
				error.throw_if("ZwOpenSection: read OBJECT_ATTRIBUTES");

				const auto name_address = reinterpret_cast<emulator_t::address_type>(object_attributes.ObjectName);

				if (name_address)
				{
					UNICODE_STRING unicode_string = { };
					error = emulator->read_virtual_memory(name_address, &unicode_string, sizeof(unicode_string));
					error.throw_if("ZwOpenSection: read UNICODE_STRING");

					const auto buffer_address = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

					if (buffer_address && unicode_string.Length)
					{
						section_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
					}
				}
			}

			spdlog::info("ZwOpenSection called (handle_address=0x{:X}, access=0x{:X}, name='{}')",
				handle_address, desired_access, section_name);

			write_nt_success(emulator);
		},
		mapped_image,
		"ZwOpenSection"
	);

	// todo: actually reference the object and write to *Object
	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto object_type = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
			emulator_t::address_type object_out = 0;
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &object_out, sizeof(object_out)));

			spdlog::info("ObReferenceObjectByHandle called (handle=0x{:X}, access=0x{:X}, type=0x{:X}, object_out=0x{:X})",
				handle, desired_access, object_type, object_out);

			write_nt_success(emulator);
		},
		mapped_image,
		"ObReferenceObjectByHandle"
	);

	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			spdlog::info("ZwMakeTemporaryObject called (handle=0x{:X})", handle);

			write_nt_success(emulator);
		},
		mapped_image,
		"ZwMakeTemporaryObject"
	);

	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, std::uint64_t>();

			spdlog::info("ZwClose called (handle=0x{:X})", handle);

			write_nt_success(emulator);
		},
		mapped_image,
		"ZwClose"
	);
}
