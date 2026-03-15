#include "nt_helpers.hpp"
#include "../../filesystem/filesystem.hpp"
#include "../../util/util.hpp"

static file_handle_t::access_type map_desired_access(const std::uint32_t desired_access)
{
	std::uint8_t access = file_handle_t::access_none;

	constexpr std::uint32_t generic_read = 0x80000000;
	constexpr std::uint32_t generic_write = 0x40000000;
	constexpr std::uint32_t generic_all = 0x10000000;
	constexpr std::uint32_t file_read_data = 0x0001;
	constexpr std::uint32_t file_write_data = 0x0002;
	constexpr std::uint32_t file_append_data = 0x0004;

	if (desired_access & (generic_read | file_read_data))
	{
		access |= file_handle_t::access_read;
	}

	if (desired_access & (generic_write | file_write_data | file_append_data))
	{
		access |= file_handle_t::access_write;
	}

	if (desired_access & generic_all)
	{
		access |= file_handle_t::access_read | file_handle_t::access_write;
	}

	return static_cast<file_handle_t::access_type>(access);
}

static std::string normalize_path(const std::wstring& guest_path)
{
	auto path = util::narrow_wstring(guest_path);

	for (auto& c : path)
	{
		if (c == '\\')
		{
			c = '/';
		}

		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}

	constexpr std::string_view device_prefix = "\\device\\";
	constexpr std::string_view nt_prefix = "\\??\\";
	constexpr std::string_view systemroot_prefix = "\\systemroot\\";

	auto strip_prefix = [](std::string& s, const std::string_view prefix)
	{
		std::string lower_prefix(prefix);

		for (auto& c : lower_prefix)
		{
			if (c == '\\')
			{
				c = '/';
			}

			c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		}

		if (s.starts_with(lower_prefix))
		{
			s = s.substr(lower_prefix.size());
		}
	};

	strip_prefix(path, device_prefix);
	strip_prefix(path, nt_prefix);
	strip_prefix(path, systemroot_prefix);

	return path;
}

static bool resolve_object_name(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type object_attributes_address,
	std::string& out_normalized_path, const std::string_view caller_name)
{
	if (!object_attributes_address)
	{
		spdlog::warn("{}: null OBJECT_ATTRIBUTES", caller_name);

		write_nt_status(emulator, 0xC000000D);

		return false;
	}

	auto object_attributes = emulator_object_t<OBJECT_ATTRIBUTES>::view_at(emulator, object_attributes_address);
	const auto oa = object_attributes.read();

	const auto object_name_address = reinterpret_cast<emulator_t::address_type>(oa.ObjectName);

	if (!object_name_address)
	{
		spdlog::warn("{}: null ObjectName", caller_name);

		write_nt_status(emulator, 0xC000000D);

		return false;
	}

	auto unicode_string_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, object_name_address);
	const auto unicode_string = unicode_string_object.read();

	const auto buffer_address = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

	if (!buffer_address || !unicode_string.Length)
	{
		spdlog::warn("{}: empty ObjectName buffer", caller_name);

		write_nt_status(emulator, 0xC000000D);

		return false;
	}

	const auto guest_path = kernel::read_guest_wstring(*emulator, buffer_address);
	const auto narrow_path = util::narrow_wstring(guest_path);

	out_normalized_path = normalize_path(guest_path);

	spdlog::info("{}: path='{}' normalized='{}'", caller_name, narrow_path, out_normalized_path);

	return true;
}

static void write_io_status(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type io_status_block_address,
	const std::int32_t status, const std::uint64_t information)
{
	if (!io_status_block_address)
	{
		return;
	}

	IO_STATUS_BLOCK io_status = { };
	io_status.Status = status;
	io_status.Information = information;

	const emulator_err_t error = emulator->write_virtual_memory(
		io_status_block_address, &io_status, sizeof(io_status));

	error.throw_if("write io status block");
}

static void write_handle_result(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type handle_out_address, const std::uint64_t handle_value)
{
	const emulator_err_t error = emulator->write_virtual_memory(
		handle_out_address, &handle_value, sizeof(handle_value));

	error.throw_if("write file handle");
}

constexpr std::uint32_t file_supersede = 0;
constexpr std::uint32_t file_open = 1;
constexpr std::uint32_t file_create = 2;
constexpr std::uint32_t file_open_if = 3;
constexpr std::uint32_t file_overwrite = 4;
constexpr std::uint32_t file_overwrite_if = 5;

constexpr std::uint64_t file_opened = 1;
constexpr std::uint64_t file_created = 2;
constexpr std::uint64_t file_superseded = 0;

static void iop_create_file(const std::shared_ptr<emulator_t>& emulator,
	const std::shared_ptr<filesystem_t>& filesystem,
	const emulator_t::address_type handle_out_address,
	const std::uint32_t desired_access,
	const emulator_t::address_type object_attributes_address,
	const emulator_t::address_type io_status_block_address,
	const std::uint32_t create_disposition,
	const std::string_view caller_name)
{
	std::string normalized;

	if (!resolve_object_name(emulator, object_attributes_address, normalized, caller_name))
	{
		return;
	}

	const auto access = map_desired_access(desired_access);

	std::shared_ptr<file_handle_t> handle;
	std::uint64_t information = 0;

	switch (create_disposition)
	{
	case file_open:
	{
		handle = filesystem->open_at(normalized, access);

		if (!handle)
		{
			spdlog::warn("{}: file not found '{}'", caller_name, normalized);

			write_io_status(emulator, io_status_block_address, static_cast<std::int32_t>(0xC0000034), 0);
			write_nt_status(emulator, 0xC0000034);

			return;
		}

		information = file_opened;

		break;
	}
	case file_create:
	{
		auto probe = filesystem->open_at(normalized);

		if (probe)
		{
			static_cast<void>(filesystem->close_handle(probe->id()));

			spdlog::warn("{}: file already exists '{}'", caller_name, normalized);

			write_io_status(emulator, io_status_block_address, static_cast<std::int32_t>(0xC0000035), 0);
			write_nt_status(emulator, 0xC0000035);

			return;
		}

		handle = filesystem->create_at(normalized, access);
		information = file_created;

		break;
	}
	case file_open_if:
	{
		handle = filesystem->open_at(normalized, access);

		if (handle)
		{
			information = file_opened;
		}
		else
		{
			handle = filesystem->create_at(normalized, access);
			information = file_created;
		}

		break;
	}
	case file_overwrite:
	{
		auto probe = filesystem->open_at(normalized);

		if (!probe)
		{
			spdlog::warn("{}: file not found for overwrite '{}'", caller_name, normalized);

			write_io_status(emulator, io_status_block_address, static_cast<std::int32_t>(0xC0000034), 0);
			write_nt_status(emulator, 0xC0000034);

			return;
		}

		static_cast<void>(filesystem->close_handle(probe->id()));
		handle = filesystem->create_at(normalized, access);
		information = file_opened;

		break;
	}
	case file_overwrite_if:
	{
		auto probe = filesystem->open_at(normalized);

		if (probe)
		{
			static_cast<void>(filesystem->close_handle(probe->id()));
			handle = filesystem->create_at(normalized, access);
			information = file_opened;
		}
		else
		{
			handle = filesystem->create_at(normalized, access);
			information = file_created;
		}

		break;
	}
	case file_supersede:
	{
		auto probe = filesystem->open_at(normalized);

		if (probe)
		{
			static_cast<void>(filesystem->close_handle(probe->id()));
		}

		handle = filesystem->create_at(normalized, access);
		information = file_superseded;

		break;
	}
	default:
	{
		spdlog::warn("{}: invalid create disposition 0x{:X}", caller_name, create_disposition);

		write_nt_status(emulator, 0xC000000D);

		return;
	}
	}

	if (!handle)
	{
		spdlog::error("{}: failed to create/open handle for '{}'", caller_name, normalized);

		write_io_status(emulator, io_status_block_address, static_cast<std::int32_t>(0xC0000001), 0);
		write_nt_status(emulator, 0xC0000001);

		return;
	}

	const std::uint64_t handle_value = handle->id();

	spdlog::info("{}: handle 0x{:X} for '{}' (access=0x{:X}, info={}, *file_handle=0x{:X})",
		caller_name, handle_value, normalized, static_cast<std::uint32_t>(access), information, handle_out_address);

	write_handle_result(emulator, handle_out_address, handle_value);
	write_io_status(emulator, io_status_block_address, 0, information);
	write_nt_success(emulator);
}

void redirect_ntoskrnl_file_functions(const std::shared_ptr<emulator_t>& emulator,
	const mapped_image_t& mapped_image,
	const std::shared_ptr<filesystem_t>& filesystem)
{
	redirect_function(
		[emulator, filesystem]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rdx = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto r8 = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto r9 = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			std::uint32_t share_access = 0;
			emulator_err_t error = emulator->read_virtual_memory(rsp + 0x28, &share_access, sizeof(share_access));
			error.throw_if("read share access");

			std::uint32_t open_options = 0;
			error = emulator->read_virtual_memory(rsp + 0x30, &open_options, sizeof(open_options));
			error.throw_if("read open options");

			spdlog::info("NtOpenFile called (file_handle_out=0x{:X}, desired_access=0x{:X}, object_attributes=0x{:X}, io_status_block=0x{:X}, share_access=0x{:X}, open_options=0x{:X})",
				rcx, rdx, r8, r9, share_access, open_options);

			iop_create_file(emulator, filesystem, rcx, rdx, r8, r9, file_open, "NtOpenFile");
		},
		mapped_image,
		"NtOpenFile"
	);

	redirect_function(
		[emulator, filesystem]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rdx = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto r8 = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto r9 = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			std::uint64_t allocation_size = 0;
			emulator_err_t error = emulator->read_virtual_memory(rsp + 0x28, &allocation_size, sizeof(allocation_size));
			error.throw_if("read allocation size ptr");

			std::uint32_t file_attributes = 0;
			error = emulator->read_virtual_memory(rsp + 0x30, &file_attributes, sizeof(file_attributes));
			error.throw_if("read file attributes");

			std::uint32_t share_access = 0;
			error = emulator->read_virtual_memory(rsp + 0x38, &share_access, sizeof(share_access));
			error.throw_if("read share access");

			std::uint32_t create_disposition = 0;
			error = emulator->read_virtual_memory(rsp + 0x40, &create_disposition, sizeof(create_disposition));
			error.throw_if("read create disposition");

			std::uint32_t create_options = 0;
			error = emulator->read_virtual_memory(rsp + 0x48, &create_options, sizeof(create_options));
			error.throw_if("read create options");

			std::uint64_t ea_buffer = 0;
			error = emulator->read_virtual_memory(rsp + 0x50, &ea_buffer, sizeof(ea_buffer));
			error.throw_if("read ea buffer");

			std::uint32_t ea_length = 0;
			error = emulator->read_virtual_memory(rsp + 0x58, &ea_length, sizeof(ea_length));
			error.throw_if("read ea length");

			spdlog::info("NtCreateFile called (file_handle_out=0x{:X}, desired_access=0x{:X}, object_attributes=0x{:X}, io_status_block=0x{:X}, allocation_size=0x{:X}, file_attributes=0x{:X}, share_access=0x{:X}, create_disposition=0x{:X}, create_options=0x{:X}, ea_buffer=0x{:X}, ea_length=0x{:X})",
				rcx, rdx, r8, r9, allocation_size, file_attributes, share_access, create_disposition, create_options, ea_buffer, ea_length);

			iop_create_file(emulator, filesystem, rcx, rdx, r8, r9, create_disposition, "NtCreateFile");
		},
		mapped_image,
		"NtCreateFile"
	);

	redirect_function(
		[emulator, filesystem]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rdx = emulator->read_register<x86::reg::rdx, std::uint32_t>();
			const auto r8 = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto r9 = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

			const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

			std::uint64_t allocation_size = 0;
			emulator_err_t error = emulator->read_virtual_memory(rsp + 0x28, &allocation_size, sizeof(allocation_size));
			error.throw_if("read allocation size ptr");

			std::uint32_t file_attributes = 0;
			error = emulator->read_virtual_memory(rsp + 0x30, &file_attributes, sizeof(file_attributes));
			error.throw_if("read file attributes");

			std::uint32_t share_access = 0;
			error = emulator->read_virtual_memory(rsp + 0x38, &share_access, sizeof(share_access));
			error.throw_if("read share access");

			std::uint32_t disposition = 0;
			error = emulator->read_virtual_memory(rsp + 0x40, &disposition, sizeof(disposition));
			error.throw_if("read disposition");

			std::uint32_t create_options = 0;
			error = emulator->read_virtual_memory(rsp + 0x48, &create_options, sizeof(create_options));
			error.throw_if("read create options");

			std::uint64_t ea_buffer = 0;
			error = emulator->read_virtual_memory(rsp + 0x50, &ea_buffer, sizeof(ea_buffer));
			error.throw_if("read ea buffer");

			std::uint32_t ea_length = 0;
			error = emulator->read_virtual_memory(rsp + 0x58, &ea_length, sizeof(ea_length));
			error.throw_if("read ea length");

			std::uint32_t create_file_type = 0;
			error = emulator->read_virtual_memory(rsp + 0x60, &create_file_type, sizeof(create_file_type));
			error.throw_if("read create file type");

			std::uint64_t internal_parameters = 0;
			error = emulator->read_virtual_memory(rsp + 0x68, &internal_parameters, sizeof(internal_parameters));
			error.throw_if("read internal parameters");

			std::uint32_t options = 0;
			error = emulator->read_virtual_memory(rsp + 0x70, &options, sizeof(options));
			error.throw_if("read options");

			std::uint64_t driver_context = 0;
			error = emulator->read_virtual_memory(rsp + 0x78, &driver_context, sizeof(driver_context));
			error.throw_if("read driver context");

			spdlog::info("IoCreateFileEx called (file_handle_out=0x{:X}, desired_access=0x{:X}, object_attributes=0x{:X}, io_status_block=0x{:X}, allocation_size=0x{:X}, file_attributes=0x{:X}, share_access=0x{:X}, disposition=0x{:X}, create_options=0x{:X}, ea_buffer=0x{:X}, ea_length=0x{:X}, create_file_type=0x{:X}, internal_parameters=0x{:X}, options=0x{:X}, driver_context=0x{:X})",
				rcx, rdx, r8, r9, allocation_size, file_attributes, share_access, disposition, create_options, ea_buffer, ea_length, create_file_type, internal_parameters, options, driver_context);

			iop_create_file(emulator, filesystem, rcx, rdx, r8, r9, disposition, "IoCreateFileEx");
		},
		mapped_image,
		"IoCreateFileEx"
	);

	const auto write_file_handler = [emulator, filesystem](const std::string_view caller_name)
	{
		const auto file_handle = emulator->read_register<x86::reg::rcx, std::uint32_t>();
		const auto event = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
		const auto apc_routine = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
		const auto apc_context = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

		const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

		emulator_t::address_type io_status_block = 0;
		emulator_err_t error = emulator->read_virtual_memory(rsp + 0x28, &io_status_block, sizeof(io_status_block));
		error.throw_if("read io status block ptr");

		emulator_t::address_type buffer_address = 0;
		error = emulator->read_virtual_memory(rsp + 0x30, &buffer_address, sizeof(buffer_address));
		error.throw_if("read buffer ptr");

		std::uint32_t length = 0;
		error = emulator->read_virtual_memory(rsp + 0x38, &length, sizeof(length));
		error.throw_if("read length");

		emulator_t::address_type byte_offset_ptr = 0;
		error = emulator->read_virtual_memory(rsp + 0x40, &byte_offset_ptr, sizeof(byte_offset_ptr));
		error.throw_if("read byte offset ptr");

		emulator_t::address_type key_ptr = 0;
		error = emulator->read_virtual_memory(rsp + 0x48, &key_ptr, sizeof(key_ptr));
		error.throw_if("read key ptr");

		spdlog::info("{} called (handle=0x{:X}, event=0x{:X}, apc_routine=0x{:X}, apc_context=0x{:X}, io_status_block=0x{:X}, buffer=0x{:X}, length=0x{:X}, byte_offset_ptr=0x{:X}, key_ptr=0x{:X})",
			caller_name, file_handle, event, apc_routine, apc_context, io_status_block, buffer_address, length, byte_offset_ptr, key_ptr);

		const auto handle = filesystem->find_handle(file_handle);

		if (!handle)
		{
			spdlog::warn("{}: invalid handle 0x{:X}", caller_name, file_handle);

			write_io_status(emulator, io_status_block, static_cast<std::int32_t>(0xC0000008), 0);
			write_nt_status(emulator, 0xC0000008);

			return;
		}

		if (!handle->can_write())
		{
			spdlog::warn("{}: handle 0x{:X} not writable", caller_name, file_handle);

			write_io_status(emulator, io_status_block, static_cast<std::int32_t>(0xC0000022), 0);
			write_nt_status(emulator, 0xC0000022);

			return;
		}

		if (!buffer_address || !length)
		{
			spdlog::warn("{}: null buffer or zero length", caller_name);

			write_io_status(emulator, io_status_block, static_cast<std::int32_t>(0xC000000D), 0);
			write_nt_status(emulator, 0xC000000D);

			return;
		}

		std::vector<std::uint8_t> buffer(length);

		error = emulator->read_virtual_memory(buffer_address, buffer.data(), length);
		error.throw_if("read write buffer from guest");

		const auto write_span = std::span<const std::uint8_t>(buffer.data(), buffer.size());

		if (!handle->write(write_span))
		{
			spdlog::error("{}: write failed for handle 0x{:X}", caller_name, file_handle);

			write_io_status(emulator, io_status_block, static_cast<std::int32_t>(0xC0000001), 0);
			write_nt_status(emulator, 0xC0000001);

			return;
		}

		spdlog::info("{}: wrote {} bytes to handle 0x{:X}", caller_name, length, file_handle);

		write_io_status(emulator, io_status_block, 0, length);
		write_nt_success(emulator);
	};

	redirect_function(
		[write_file_handler] { write_file_handler("NtWriteFile"); },
		mapped_image, "NtWriteFile"
	);

	redirect_function(
		[write_file_handler] { write_file_handler("ZwWriteFile"); },
		mapped_image, "ZwWriteFile"
	);

	redirect_function(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto rdx = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			spdlog::info("ZwFlushBuffersFile called (handle=0x{:X}, io_status_block=0x{:X})", rcx, rdx);

			write_io_status(emulator, rdx, 0, 0);
			write_nt_success(emulator);
		},
		mapped_image, "ZwFlushBuffersFile"
	);
}
