#include "flt_misc.hpp"

static void handle_flt_acquire_push_lock_exclusive(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type push_lock)
{
	THREAD_LOG("FltAcquirePushLockExclusive called (push_lock=0x{:X})", push_lock);
}

static void handle_flt_acquire_push_lock_shared(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type push_lock)
{
	THREAD_LOG("FltAcquirePushLockShared called (push_lock=0x{:X})", push_lock);
}

static void handle_flt_release_push_lock(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type push_lock)
{
	THREAD_LOG("FltReleasePushLock called (push_lock=0x{:X})", push_lock);
}

static void handle_flt_register_filter(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type driver_object, emulator_t::address_type registration,
	emulator_t::address_type ret_filter)
{
	THREAD_LOG("FltRegisterFilter called (driver=0x{:X}, registration=0x{:X}, ret_filter=0x{:X})",
		driver_object, registration, ret_filter);

	// allocate a fake filter object
	if (ret_filter)
	{
		const auto fake_filter = emulator->heap_allocate(0x100, prot_read_write, true);
		emulator_err_t error = fake_filter.error_or({});
		error.throw_if("FltRegisterFilter: allocate fake filter");

		error = emulator->write_virtual_memory(ret_filter, &fake_filter.value(), sizeof(fake_filter.value()));
		error.throw_if("FltRegisterFilter: write filter pointer");
	}

	write_nt_success(emulator);
}

static void handle_flt_start_filtering(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type filter)
{
	THREAD_LOG("FltStartFiltering called (filter=0x{:X})", filter);

	write_nt_success(emulator);
}

static void handle_flt_unregister_filter(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type filter)
{
	THREAD_LOG("FltUnregisterFilter called (filter=0x{:X})", filter);
}

static void handle_flt_build_default_security_descriptor(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type sd_out, std::uint32_t desired_access)
{
	THREAD_LOG("FltBuildDefaultSecurityDescriptor called (sd_out=0x{:X}, desired_access=0x{:X})",
		sd_out, desired_access);

	if (sd_out)
	{
		const auto fake_sd = emulator->heap_allocate(0x40, prot_read_write, true);
		auto error = fake_sd.error_or({});
		error.throw_if("FltBuildDefaultSecurityDescriptor: allocate fake SD");

		error = emulator->write_virtual_memory(sd_out, &fake_sd.value(), sizeof(fake_sd.value()));
		error.throw_if("FltBuildDefaultSecurityDescriptor: write SD pointer");
	}

	write_nt_success(emulator);
}

static void handle_flt_free_security_descriptor(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type sd)
{
	THREAD_LOG("FltFreeSecurityDescriptor called (sd=0x{:X})", sd);
}

static void handle_flt_create_communication_port(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type filter, emulator_t::address_type object_attributes,
	emulator_t::address_type server_port_out, emulator_t::address_type connect_notify)
{
	THREAD_LOG("FltCreateCommunicationPort called (filter=0x{:X}, oa=0x{:X}, server_port_out=0x{:X}, connect_notify=0x{:X})",
		filter, object_attributes, server_port_out, connect_notify);

	if (server_port_out)
	{
		const auto fake_port = emulator->heap_allocate(0x100, prot_read_write, true);
		auto error = fake_port.error_or({});
		error.throw_if("FltCreateCommunicationPort: allocate fake port");

		error = emulator->write_virtual_memory(server_port_out, &fake_port.value(), sizeof(fake_port.value()));
		error.throw_if("FltCreateCommunicationPort: write port pointer");
	}

	write_nt_success(emulator);
}

static void handle_flt_close_communication_port(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type server_port)
{
	THREAD_LOG("FltCloseCommunicationPort called (server_port=0x{:X})", server_port);
}

static void handle_flt_close_client_port(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type client_port)
{
	THREAD_LOG("FltCloseClientPort called (client_port=0x{:X})", client_port);
}

static void handle_flt_get_file_name_information_unsafe(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type file_object, emulator_t::address_type instance,
	std::uint32_t name_options, emulator_t::address_type file_name_info_out)
{
	THREAD_LOG("FltGetFileNameInformationUnsafe called (file_object=0x{:X}, instance=0x{:X}, name_options=0x{:X}, out=0x{:X})",
		file_object, instance, name_options, file_name_info_out);

	if (file_name_info_out)
	{
		// try to find the file path from the object manager
		std::wstring fake_name = L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntoskrnl.exe";

		const auto file_obj = kernel::object_manager->get_object<file_object_t>(file_object);
		if (file_obj && !file_obj->path.empty())
		{
			fake_name = util::widen_string(file_obj->path);
		}

		const auto byte_len = static_cast<std::uint16_t>(fake_name.size() * sizeof(wchar_t));

		const std::uint64_t struct_size = 0x60;
		const auto alloc = emulator->heap_allocate(struct_size + byte_len + sizeof(wchar_t), prot_read_write, true);
		auto error = alloc.error_or({});
		error.throw_if("FltGetFileNameInformationUnsafe: allocate name info");

		const auto alloc_addr = *alloc;
		const auto buffer_addr = alloc_addr + struct_size;

		// write the Name UNICODE_STRING at offset 0x08 in the struct
		UNICODE_STRING us{};
		us.Length = byte_len;
		us.MaximumLength = byte_len + sizeof(wchar_t);
		us.Buffer = reinterpret_cast<wchar_t*>(buffer_addr);

		error = emulator->write_virtual_memory(alloc_addr + 0x08, &us, sizeof(us));
		error.throw_if("FltGetFileNameInformationUnsafe: write Name field");

		error = emulator->write_virtual_memory(buffer_addr, fake_name.data(), byte_len);
		error.throw_if("FltGetFileNameInformationUnsafe: write name buffer");

		error = emulator->write_virtual_memory(file_name_info_out, &alloc_addr, sizeof(alloc_addr));
		error.throw_if("FltGetFileNameInformationUnsafe: write output pointer");
	}

	write_nt_success(emulator);
}

static void handle_flt_release_file_name_information(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type file_name_info)
{
	THREAD_LOG("FltReleaseFileNameInformation called (info=0x{:X})", file_name_info);
}

static void handle_flt_parse_file_name_information(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type file_name_info)
{
	THREAD_LOG("FltParseFileNameInformation called (info=0x{:X})", file_name_info);

	write_nt_success(emulator);
}

void redirect_fltmgr_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_flt_acquire_push_lock_exclusive>(emulator, mapped_image, "FltAcquirePushLockExclusive");
	redirect_handler<handle_flt_acquire_push_lock_shared>(emulator, mapped_image, "FltAcquirePushLockShared");
	redirect_handler<handle_flt_release_push_lock>(emulator, mapped_image, "FltReleasePushLock");
	redirect_handler<handle_flt_register_filter>(emulator, mapped_image, "FltRegisterFilter");
	redirect_handler<handle_flt_start_filtering>(emulator, mapped_image, "FltStartFiltering");
	redirect_handler<handle_flt_unregister_filter>(emulator, mapped_image, "FltUnregisterFilter");
	redirect_handler<handle_flt_build_default_security_descriptor>(emulator, mapped_image, "FltBuildDefaultSecurityDescriptor");
	redirect_handler<handle_flt_free_security_descriptor>(emulator, mapped_image, "FltFreeSecurityDescriptor");
	redirect_handler<handle_flt_create_communication_port>(emulator, mapped_image, "FltCreateCommunicationPort");
	redirect_handler<handle_flt_close_communication_port>(emulator, mapped_image, "FltCloseCommunicationPort");
	redirect_handler<handle_flt_close_client_port>(emulator, mapped_image, "FltCloseClientPort");
	redirect_handler<handle_flt_get_file_name_information_unsafe>(emulator, mapped_image, "FltGetFileNameInformationUnsafe");
	redirect_handler<handle_flt_release_file_name_information>(emulator, mapped_image, "FltReleaseFileNameInformation");
	redirect_handler<handle_flt_parse_file_name_information>(emulator, mapped_image, "FltParseFileNameInformation");
}
