#include "nt_helpers.hpp"
#include "../../kernel/exception.hpp"
#include "../../user/user.hpp"

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
	const image_t& mapped_image)
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

// todo: actually delete the symbolic link from the object namespace
static void handle_delete_symbolic_link(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type name_address)
{
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
}

static void handle_reference_object_by_handle(const std::shared_ptr<emulator_t>& emulator,
	kernel::handle_t handle, std::uint32_t desired_access, emulator_t::address_type object_type,
	emulator_t::address_type access_mode, emulator_t::address_type object_out)
{
	THREAD_LOG("ObReferenceObjectByHandle called (handle=0x{:X}, access=0x{:X}, type=0x{:X}, object_out=0x{:X})",
		handle, desired_access, object_type, object_out);

	const auto entry = kernel::active_handle_table().lookup_handle(handle);

	if (entry && object_out)
	{
		kernel::object_manager->reference_object(entry->body_address);

		emulator_err_t error = emulator->write_virtual_memory(object_out, &entry->body_address, sizeof(entry->body_address));
		error.throw_if("ObReferenceObjectByHandle: write Object");

		THREAD_LOG("ObReferenceObjectByHandle: resolved handle 0x{:X} -> body 0x{:X}", handle, entry->body_address);
	}

	write_nt_success(emulator);
}

static void handle_make_temporary_object(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle)
{
	THREAD_LOG("ZwMakeTemporaryObject called (handle=0x{:X})", handle);

	write_nt_success(emulator);
}

static void handle_close(const std::shared_ptr<emulator_t>& emulator,
	kernel::handle_t handle)
{
	THREAD_LOG("NtClose called (handle=0x{:X})", handle);

	if (!user::is_console_handle(handle))
	{
		kernel::active_handle_table().close_handle(handle);
	}

	write_nt_success(emulator);
}

// todo: actually register object callbacks
static void handle_register_callbacks(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type registration_address, emulator_t::address_type handle_out)
{
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
}

static void handle_unregister_callbacks(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type registration_handle)
{
	THREAD_LOG("ObUnRegisterCallbacks called (handle=0x{:X})", registration_handle);
}

static void handle_open_directory_object(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle_address, std::uint32_t desired_access,
	emulator_t::address_type object_attributes_address)
{
	std::string directory_name;

	if (object_attributes_address)
	{
		OBJECT_ATTRIBUTES object_attributes = {};
		emulator_err_t error = emulator->read_virtual_memory(object_attributes_address, &object_attributes, sizeof(object_attributes));
		error.throw_if("OpenDirectoryObject: read OBJECT_ATTRIBUTES");

		const auto name_address = reinterpret_cast<emulator_t::address_type>(object_attributes.ObjectName);

		if (name_address)
		{
			UNICODE_STRING unicode_string = {};
			error = emulator->read_virtual_memory(name_address, &unicode_string, sizeof(unicode_string));
			error.throw_if("OpenDirectoryObject: read UNICODE_STRING");

			const auto buffer_address = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

			if (buffer_address && unicode_string.Length)
			{
				directory_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
			}
		}
	}

	auto host_object = std::make_shared<directory_object_t>(directory_name);

	constexpr std::size_t directory_body_size = 0x40;
	std::array<std::uint8_t, directory_body_size> body{};
	const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size(), host_object);
	const auto handle_value = kernel::active_handle_table().create_handle(body_address, desired_access);

	if (handle_address)
	{
		emulator_err_t error = emulator->write_virtual_memory(handle_address, &handle_value, sizeof(handle_value));
		error.throw_if("OpenDirectoryObject: write handle");
	}

	THREAD_LOG("NtOpenDirectoryObject called (handle_address=0x{:X}, access=0x{:X}, name='{}') -> handle=0x{:X}",
		handle_address, desired_access, directory_name, handle_value);

	write_nt_success(emulator);
}

static void handle_reference_object(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type object)
{
	THREAD_LOG("ObfReferenceObject called (object=0x{:X})", object);

	kernel::object_manager->reference_object(object);
}

static void handle_dereference_object(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type object)
{
	THREAD_LOG("ObfDereferenceObject called (object=0x{:X})", object);

	kernel::object_manager->dereference_object(object);
}

static void handle_reference_process_handle_table(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type process_address)
{
	emulator_t::address_type object_table = 0;
	static_cast<void>(emulator->read_virtual_memory(process_address + offsetof(_EPROCESS, ObjectTable),
		&object_table, sizeof(object_table)));

	THREAD_LOG("ObReferenceProcessHandleTable called (process=0x{:X}) -> 0x{:X}",
		process_address, object_table);

	write_return_value(emulator, object_table);
}

static void handle_dereference_process_handle_table(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type process_address)
{
	THREAD_LOG("ObDereferenceProcessHandleTable called (process=0x{:X})", process_address);
}

static void handle_enum_handle_table(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle_table, emulator_t::address_type callback,
	emulator_t::address_type context, emulator_t::address_type handle_out)
{
	THREAD_LOG("ExEnumHandleTable called (table=0x{:X}, callback=0x{:X}, context=0x{:X}, handle_out=0x{:X})",
		handle_table, callback, context, handle_out);

	if (handle_out)
	{
		emulator_t::address_type zero = 0;
		static_cast<void>(emulator->write_virtual_memory(handle_out, &zero, sizeof(zero)));
	}

	write_return_value(emulator, static_cast<std::uint64_t>(0));
}

static void handle_get_object_type(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type object_address)
{
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
}

static void handle_open_object_by_pointer(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type object_address, std::uint32_t handle_attributes,
	emulator_t::address_type access_state, std::uint32_t desired_access,
	emulator_t::address_type object_type, std::uint32_t access_mode,
	emulator_t::address_type handle_out)
{
	THREAD_LOG("ObOpenObjectByPointer called (object=0x{:X}, attrs=0x{:X}, access=0x{:X}, "
		"type=0x{:X}, mode={}, handle_out=0x{:X})",
		object_address, handle_attributes, desired_access, object_type, access_mode, handle_out);

	kernel::object_manager->reference_object(object_address);

	const auto handle_value = kernel::active_handle_table().create_handle(object_address, desired_access);

	if (handle_out)
	{
		emulator_err_t error = emulator->write_virtual_memory(handle_out, &handle_value, sizeof(handle_value));
		error.throw_if("ObOpenObjectByPointer: write handle");
	}

	THREAD_LOG("ObOpenObjectByPointer: created handle 0x{:X} for object 0x{:X}",
		handle_value, object_address);

	write_nt_success(emulator);
}

void redirect_ntoskrnl_object_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_delete_symbolic_link>(emulator, mapped_image, "IoDeleteSymbolicLink");

	redirect_handler<handle_reference_object_by_handle>(emulator, mapped_image, "ObReferenceObjectByHandle");

	redirect_handler<handle_make_temporary_object>(emulator, mapped_image, "ZwMakeTemporaryObject");

	redirect_handler<handle_close>(emulator, mapped_image, "NtClose");
	redirect_handler<handle_close>(emulator, mapped_image, "ZwClose");

	redirect_handler<handle_register_callbacks>(emulator, mapped_image, "ObRegisterCallbacks");

	redirect_handler<handle_unregister_callbacks>(emulator, mapped_image, "ObUnRegisterCallbacks");

	redirect_handler<handle_open_directory_object>(emulator, mapped_image, "NtOpenDirectoryObject");
	redirect_handler<handle_open_directory_object>(emulator, mapped_image, "ZwOpenDirectoryObject");

	redirect_handler<handle_reference_object>(emulator, mapped_image, "ObfReferenceObject");

	redirect_handler<handle_dereference_object>(emulator, mapped_image, "ObfDereferenceObject");
	redirect_handler<handle_dereference_object>(emulator, mapped_image, "ObfDereferenceObjectWithTag");

	redirect_handler<handle_reference_process_handle_table>(emulator, mapped_image, "ObReferenceProcessHandleTable");

	redirect_handler<handle_dereference_process_handle_table>(emulator, mapped_image, "ObDereferenceProcessHandleTable");

	redirect_handler<handle_enum_handle_table>(emulator, mapped_image, "ExEnumHandleTable");

	redirect_handler<handle_get_object_type>(emulator, mapped_image, "ObGetObjectType");

	redirect_handler<handle_open_object_by_pointer>(emulator, mapped_image, "ObOpenObjectByPointer");
}
