#include "nt_helpers.hpp"

static emulator_object_t<_OBJECT_TYPE> create_object_type(const std::shared_ptr<emulator_t>& emulator,
	const std::wstring_view name, const std::string& object_name)
{
	auto object = emulator_object_t<_OBJECT_TYPE>::allocate(emulator, object_name);

	const auto unicode_name = kernel::init_unicode_string(*emulator, name);
	emulator_err_t error = emulator->write_virtual_memory(
		object.address() + offsetof(_OBJECT_TYPE, Name), &unicode_name, sizeof(unicode_name));
	error.throw_if("write _OBJECT_TYPE.Name");

	return object;
}

void initialize_ntoskrnl_object_types(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	auto process_type = create_object_type(emulator, L"Process", "PsProcessType");
	auto thread_type = create_object_type(emulator, L"Thread", "PsThreadType");

	if (const auto symbol = mapped_image.find_symbol("PsProcessType"))
	{
		const auto address = process_type.address();
		emulator_err_t error = emulator->write_virtual_memory(*symbol, &address, sizeof(address));
		error.throw_if("write PsProcessType");
	}

	if (const auto symbol = mapped_image.find_symbol("PsThreadType"))
	{
		const auto address = thread_type.address();
		emulator_err_t error = emulator->write_virtual_memory(*symbol, &address, sizeof(address));
		error.throw_if("write PsThreadType");
	}
}

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

	// todo: actually register object callbacks
	redirect_function(
		[emulator]
		{
			const auto registration_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto handle_out = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			_OB_CALLBACK_REGISTRATION registration = { };
			emulator_err_t error = emulator->read_virtual_memory(registration_address, &registration, sizeof(registration));
			error.throw_if("ObRegisterCallbacks: read registration");

			const auto altitude_buffer = reinterpret_cast<emulator_t::address_type>(registration.Altitude.Buffer);
			std::string altitude_string;

			if (altitude_buffer && registration.Altitude.Length)
			{
				altitude_string = util::narrow_wstring(kernel::read_guest_wstring(*emulator, altitude_buffer));
			}

			spdlog::info("ObRegisterCallbacks called (version={}, altitude='{}', operation_count={})",
				registration.Version, altitude_string, registration.OperationRegistrationCount);

			const auto op_array_address = reinterpret_cast<emulator_t::address_type>(registration.OperationRegistration);

			for (std::uint16_t i = 0; i < registration.OperationRegistrationCount; ++i)
			{
				_OB_OPERATION_REGISTRATION op = { };
				error = emulator->read_virtual_memory(
					op_array_address + i * sizeof(_OB_OPERATION_REGISTRATION), &op, sizeof(op));
				error.throw_if("ObRegisterCallbacks: read operation registration");

				const auto object_type_ptr = reinterpret_cast<emulator_t::address_type>(op.ObjectType);

				std::string type_name = std::format("0x{:X}", object_type_ptr);

				if (const auto ntoskrnl = kernel::find_module("ntoskrnl.exe"))
				{
					if (const auto symbol = ntoskrnl->find_symbol_by_address(object_type_ptr))
					{
						if (symbol->second == object_type_ptr)
						{
							type_name = symbol->first;
						}
					}
				}

				spdlog::info("  operation[{}]: type={}, operations=0x{:X}, pre=0x{:X}, post=0x{:X}",
					i, type_name, op.Operations,
					reinterpret_cast<emulator_t::address_type>(op.PreOperation),
					reinterpret_cast<emulator_t::address_type>(op.PostOperation));
			}

			if (handle_out)
			{
				const auto dummy_handle = emulator->heap_allocate(8, prot_read_write, true);
				error = dummy_handle.error_or({});
				error.throw_if("allocate ObRegisterCallbacks handle");

				error = emulator->write_virtual_memory(handle_out, &*dummy_handle, sizeof(*dummy_handle));
				error.throw_if("write ObRegisterCallbacks handle");
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"ObRegisterCallbacks"
	);
}
