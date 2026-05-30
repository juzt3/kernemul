#include "flt_misc.hpp"

void redirect_fltmgr_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			const auto push_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltAcquirePushLockExclusive called (push_lock=0x{:X})", push_lock);
		},
		mapped_image,
		"FltAcquirePushLockExclusive"
	);

	redirect_function(
		[emulator]
		{
			const auto push_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltAcquirePushLockShared called (push_lock=0x{:X})", push_lock);
		},
		mapped_image,
		"FltAcquirePushLockShared"
	);

	redirect_function(
		[emulator]
		{
			const auto push_lock = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltReleasePushLock called (push_lock=0x{:X})", push_lock);
		},
		mapped_image,
		"FltReleasePushLock"
	);

	redirect_function(
		[emulator]
		{
			const auto driver_object = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto registration = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto ret_filter = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

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
		},
		mapped_image,
		"FltRegisterFilter"
	);

	redirect_function(
		[emulator]
		{
			const auto filter = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltStartFiltering called (filter=0x{:X})", filter);

			write_nt_success(emulator);
		},
		mapped_image,
		"FltStartFiltering"
	);

	redirect_function(
		[emulator]
		{
			const auto filter = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltUnregisterFilter called (filter=0x{:X})", filter);
		},
		mapped_image,
		"FltUnregisterFilter"
	);

	redirect_function(
		[emulator]
		{
			const auto sd_out = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto desired_access = emulator->read_register<x86::reg::rdx, std::uint32_t>();

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
		},
		mapped_image,
		"FltBuildDefaultSecurityDescriptor"
	);

	redirect_function(
		[emulator]
		{
			const auto sd = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltFreeSecurityDescriptor called (sd=0x{:X})", sd);
		},
		mapped_image,
		"FltFreeSecurityDescriptor"
	);

	redirect_function(
		[emulator]
		{
			const auto filter = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto object_attributes = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto server_port_out = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto connect_notify = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

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
		},
		mapped_image,
		"FltCreateCommunicationPort"
	);

	redirect_function(
		[emulator]
		{
			const auto server_port = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltCloseCommunicationPort called (server_port=0x{:X})", server_port);
		},
		mapped_image,
		"FltCloseCommunicationPort"
	);

	redirect_function(
		[emulator]
		{
			const auto client_port = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltCloseClientPort called (client_port=0x{:X})", client_port);
		},
		mapped_image,
		"FltCloseClientPort"
	);

	redirect_function(
		[emulator]
		{
			const auto file_object = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto instance = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto name_options = emulator->read_register<x86::reg::r8, std::uint32_t>();
			const auto file_name_info_out = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

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
		},
		mapped_image,
		"FltGetFileNameInformationUnsafe"
	);

	redirect_function(
		[emulator]
		{
			const auto file_name_info = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltReleaseFileNameInformation called (info=0x{:X})", file_name_info);
		},
		mapped_image,
		"FltReleaseFileNameInformation"
	);

	redirect_function(
		[emulator]
		{
			const auto file_name_info = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("FltParseFileNameInformation called (info=0x{:X})", file_name_info);

			write_nt_success(emulator);
		},
		mapped_image,
		"FltParseFileNameInformation"
	);
}
