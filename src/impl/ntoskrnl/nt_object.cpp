#include "nt_helpers.hpp"
#include "../../kernel/exception.hpp"

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
	auto file_type = create_object_type(emulator, L"File", "IoFileObjectType");

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

	if (const auto symbol = mapped_image.find_symbol("IoFileObjectType"))
	{
		const auto address = file_type.address();
		emulator_err_t error = emulator->write_virtual_memory(*symbol, &address, sizeof(address));
		error.throw_if("write IoFileObjectType");
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

			THREAD_LOG("IoDeleteSymbolicLink called (name='{}')", link_name);

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

			THREAD_LOG("ZwOpenSection called (handle_address=0x{:X}, access=0x{:X}, name='{}')",
				handle_address, desired_access, section_name);

			auto host_object = std::make_shared<section_object_t>(nullptr);

			constexpr std::size_t section_body_size = 0x40;
			std::array<std::uint8_t, section_body_size> body{};
			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size(), host_object);
			const auto handle_value = kernel::object_manager->create_handle(body_address, desired_access);

			if (handle_address)
			{
				emulator_err_t error = emulator->write_virtual_memory(handle_address, &handle_value, sizeof(handle_value));
				error.throw_if("ZwOpenSection: write handle");
			}

			THREAD_LOG("ZwOpenSection: created handle 0x{:X} for section '{}' at 0x{:X}",
				handle_value, section_name, body_address);

			write_nt_success(emulator);
		},
		mapped_image,
		"ZwOpenSection"
	);

	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, object_manager_t::handle_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto object_type = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
			emulator_t::address_type object_out = 0;
			emulator_err_t error = emulator->read_virtual_memory(rsp + 0x28, &object_out, sizeof(object_out));
			error.throw_if("ObReferenceObjectByHandle: read Object");

			THREAD_LOG("ObReferenceObjectByHandle called (handle=0x{:X}, access=0x{:X}, type=0x{:X}, object_out=0x{:X})",
				handle, desired_access, object_type, object_out);

			const auto entry = kernel::object_manager->lookup_handle(handle);

			if (entry && object_out)
			{
				kernel::object_manager->reference_object(entry->body_address);

				error = emulator->write_virtual_memory(object_out, &entry->body_address, sizeof(entry->body_address));
				error.throw_if("ObReferenceObjectByHandle: write Object");

				THREAD_LOG("ObReferenceObjectByHandle: resolved handle 0x{:X} -> body 0x{:X}", handle, entry->body_address);
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"ObReferenceObjectByHandle"
	);

	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("ZwMakeTemporaryObject called (handle=0x{:X})", handle);

			write_nt_success(emulator);
		},
		mapped_image,
		"ZwMakeTemporaryObject"
	);

	const auto close_handler = [emulator](const std::string_view caller_name)
	{
		const auto handle = emulator->read_register<x86::reg::rcx, object_manager_t::handle_type>();

		THREAD_LOG("{} called (handle=0x{:X})", caller_name, handle);

		kernel::object_manager->close_handle(handle);

		write_nt_success(emulator);
	};

	redirect_function(
		[close_handler] { close_handler("NtClose"); },
		mapped_image, "NtClose"
	);

	redirect_function(
		[close_handler] { close_handler("ZwClose"); },
		mapped_image, "ZwClose"
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

			THREAD_LOG("ObRegisterCallbacks called (version={}, altitude='{}', operation_count={})",
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

				THREAD_LOG("  operation[{}]: type={}, operations=0x{:X}, pre=0x{:X}, post=0x{:X}",
					i, type_name, op.Operations,
					reinterpret_cast<emulator_t::address_type>(op.PreOperation),
					reinterpret_cast<emulator_t::address_type>(op.PostOperation));
			}

			if (handle_out)
			{
				auto host_object = std::make_shared<ob_callback_object_t>();

				constexpr std::size_t ob_callback_body_size = 8;
				std::array<std::uint8_t, ob_callback_body_size> body{};
				const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size(), host_object);

				error = emulator->write_virtual_memory(handle_out, &body_address, sizeof(body_address));
				error.throw_if("write ObRegisterCallbacks handle");
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"ObRegisterCallbacks"
	);

	redirect_function(
		[emulator]
		{
			const auto handle_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto object_attributes_address = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			std::string directory_name;

			if (object_attributes_address)
			{
				OBJECT_ATTRIBUTES object_attributes = {};
				emulator_err_t error = emulator->read_virtual_memory(object_attributes_address, &object_attributes, sizeof(object_attributes));
				error.throw_if("NtOpenDirectoryObject: read OBJECT_ATTRIBUTES");

				const auto name_address = reinterpret_cast<emulator_t::address_type>(object_attributes.ObjectName);

				if (name_address)
				{
					UNICODE_STRING unicode_string = {};
					error = emulator->read_virtual_memory(name_address, &unicode_string, sizeof(unicode_string));
					error.throw_if("NtOpenDirectoryObject: read UNICODE_STRING");

					const auto buffer_address = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

					if (buffer_address && unicode_string.Length)
					{
						directory_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
					}
				}
			}

			constexpr std::size_t directory_body_size = 0x40;
			std::array<std::uint8_t, directory_body_size> body{};
			const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size());
			const auto handle_value = kernel::object_manager->create_handle(body_address, desired_access);

			if (handle_address)
			{
				emulator_err_t error = emulator->write_virtual_memory(handle_address, &handle_value, sizeof(handle_value));
				error.throw_if("NtOpenDirectoryObject: write handle");
			}

			THREAD_LOG("NtOpenDirectoryObject called (handle_address=0x{:X}, access=0x{:X}, name='{}') -> handle=0x{:X}",
				handle_address, desired_access, directory_name, handle_value);

			write_nt_success(emulator);
		},
		mapped_image,
		"NtOpenDirectoryObject"
	);

	redirect_function(
		[emulator]
		{
			const auto object = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("ObfReferenceObject called (object=0x{:X})", object);

			kernel::object_manager->reference_object(object);
		},
		mapped_image,
		"ObfReferenceObject"
	);

	const auto dereference_handler = [emulator](const std::string_view caller_name)
	{
		const auto object = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

		THREAD_LOG("{} called (object=0x{:X})", caller_name, object);

		kernel::object_manager->dereference_object(object);
	};

	redirect_function(
		[dereference_handler] { dereference_handler("ObfDereferenceObject"); },
		mapped_image,
		"ObfDereferenceObject"
	);

	redirect_function(
		[dereference_handler] { dereference_handler("ObfDereferenceObjectWithTag"); },
		mapped_image,
		"ObfDereferenceObjectWithTag"
	);

	redirect_function(
		[emulator]
		{
			const auto object_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			const char* type_symbol = nullptr;
			const auto host_object = kernel::object_manager->get_object<object_t>(object_address);

			if (host_object)
			{
				if (dynamic_cast<file_object_t*>(host_object.get()))
					type_symbol = "IoFileObjectType";
				else if (dynamic_cast<thread_object_t*>(host_object.get()))
					type_symbol = "PsThreadType";
			}

			emulator_t::address_type type_object = 0;

			if (type_symbol)
			{
				if (const auto ntoskrnl = kernel::find_module("ntoskrnl.exe"))
				{
					if (const auto symbol = ntoskrnl->find_symbol(type_symbol))
					{
						(void)emulator->read_virtual_memory(*symbol, &type_object, sizeof(type_object));
					}
				}
			}

			THREAD_LOG("ObGetObjectType called (object=0x{:X}, type={}) -> 0x{:X}",
				object_address, type_symbol ? type_symbol : "unknown", type_object);

			write_return_value(emulator, type_object);
		},
		mapped_image,
		"ObGetObjectType"
	);

	redirect_function(
		[emulator]
		{
			const auto object_address = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto handle_attributes = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto access_state = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::r9, std::uint32_t>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			emulator_t::address_type object_type = 0;
			std::uint32_t access_mode = 0;
			emulator_t::address_type handle_out = 0;

			static_cast<void>(emulator->read_virtual_memory(rsp + 0x28, &object_type, sizeof(object_type)));
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x30, &access_mode, sizeof(access_mode)));
			static_cast<void>(emulator->read_virtual_memory(rsp + 0x38, &handle_out, sizeof(handle_out)));

			THREAD_LOG("ObOpenObjectByPointer called (object=0x{:X}, attrs=0x{:X}, access=0x{:X}, "
				"type=0x{:X}, mode={}, handle_out=0x{:X})",
				object_address, handle_attributes, desired_access, object_type, access_mode, handle_out);

			kernel::object_manager->reference_object(object_address);

			const auto handle_value = kernel::object_manager->create_handle(object_address, desired_access);

			if (handle_out)
			{
				emulator_err_t error = emulator->write_virtual_memory(handle_out, &handle_value, sizeof(handle_value));
				error.throw_if("ObOpenObjectByPointer: write handle");
			}

			THREAD_LOG("ObOpenObjectByPointer: created handle 0x{:X} for object 0x{:X}",
				handle_value, object_address);

			write_nt_success(emulator);
		},
		mapped_image,
		"ObOpenObjectByPointer"
	);
}
