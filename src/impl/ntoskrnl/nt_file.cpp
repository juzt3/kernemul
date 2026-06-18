#include "nt_helpers.hpp"
#include "../../util/util.hpp"
#include "../../user/user.hpp"

#include <cstdio>

constexpr std::size_t file_object_body_size = 0x1d8;

struct file_directory_information_t
{
	std::uint32_t next_entry_offset;
	std::uint32_t file_index;
	std::int64_t creation_time;
	std::int64_t last_access_time;
	std::int64_t last_write_time;
	std::int64_t change_time;
	std::int64_t end_of_file;
	std::int64_t allocation_size;
	std::uint32_t file_attributes;
	std::uint32_t file_name_length;
};

static_assert(sizeof(file_directory_information_t) == 0x40, "FILE_DIRECTORY_INFORMATION header must be 0x40 bytes");

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

	// strip harddiskvolumeN/ or harddiskvolumN/windows/ prefixes
	{
		const auto hdv_pos = path.find("harddiskvolume");

		if (hdv_pos == 0)
		{
			auto slash = path.find('/', hdv_pos);

			if (slash != std::string::npos)
			{
				path = path.substr(slash + 1);

				// also strip "windows/" to normalize to system32/ paths
				if (path.starts_with("windows/"))
				{
					path = path.substr(8);
				}
			}
		}
	}

	// strip drive letter prefix (e.g. "c:/")
	if (path.size() >= 3
		&& std::isalpha(static_cast<unsigned char>(path[0]))
		&& path[1] == ':'
		&& path[2] == '/')
	{
		path = path.substr(3);
	}

	// strip "windows/" prefix to normalize to system32-relative paths
	if (path.starts_with("windows/"))
	{
		path = path.substr(8);
	}

	// handle bare /systemroot with no trailing slash
	if (path == "/systemroot")
	{
		path = "windows";
	}

	// strip trailing slashes
	while (!path.empty() && path.back() == '/')
	{
		path.pop_back();
	}

	return path;
}

static bool resolve_object_name(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type object_attributes_address,
	std::string& out_normalized_path, const std::string_view caller_name)
{
	if (!object_attributes_address)
	{
		THREAD_WARN_LOG("{}: null OBJECT_ATTRIBUTES", caller_name);

		write_nt_status(emulator, 0xC000000D);

		return false;
	}

	auto object_attributes = emulator_object_t<OBJECT_ATTRIBUTES>::view_at(emulator, object_attributes_address);
	const auto oa = object_attributes.read();

	const auto object_name_address = reinterpret_cast<emulator_t::address_type>(oa.ObjectName);

	if (!object_name_address)
	{
		THREAD_WARN_LOG("{}: null ObjectName", caller_name);

		write_nt_status(emulator, 0xC000000D);

		return false;
	}

	auto unicode_string_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, object_name_address);
	const auto unicode_string = unicode_string_object.read();

	const auto buffer_address = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

	if (!buffer_address || !unicode_string.Length)
	{
		THREAD_WARN_LOG("{}: empty ObjectName buffer", caller_name);

		write_nt_status(emulator, 0xC000000D);

		return false;
	}

	const auto guest_path = kernel::read_guest_wstring(*emulator, buffer_address);
	const auto narrow_path = util::narrow_wstring(guest_path);

	out_normalized_path = normalize_path(guest_path);

	THREAD_LOG("{}: path='{}' normalized='{}'", caller_name, narrow_path, out_normalized_path);

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

constexpr std::uint32_t file_directory_file = 0x00000001;
constexpr std::uint32_t file_non_directory_file = 0x00000040;

constexpr std::uint32_t status_object_name_not_found = 0xC0000034;
constexpr std::uint32_t status_object_name_collision = 0xC0000035;
constexpr std::uint32_t status_invalid_parameter = 0xC000000D;
constexpr std::uint32_t status_file_is_a_directory = 0xC00000BA;
constexpr std::uint32_t status_not_a_directory = 0xC0000103;
constexpr std::uint32_t status_unsuccessful = 0xC0000001;
constexpr std::uint32_t status_no_more_files = 0x80000006;
constexpr std::uint32_t status_no_such_file = 0xC000000F;
constexpr std::uint32_t status_buffer_overflow = 0x80000005;

static void iop_create_file(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type handle_out_address,
	const std::uint32_t desired_access,
	const emulator_t::address_type object_attributes_address,
	const emulator_t::address_type io_status_block_address,
	const std::uint32_t create_disposition,
	const std::uint32_t create_options,
	const std::string_view caller_name)
{
	std::string normalized;

	if (!resolve_object_name(emulator, object_attributes_address, normalized, caller_name))
	{
		return;
	}

	// intercept console device paths and return pseudo-handles
	{
		std::string upper = normalized;

		for (auto& c : upper)
		{
			c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
		}

		if (upper == "CONOUT$" || upper == "CON"
			|| upper.ends_with("/CONOUT$") || upper.ends_with("/CON")
			|| upper.ends_with("/CONSOLE"))
		{
			THREAD_LOG("{}: console output device '{}' -> pseudo-handle 0x{:X}",
				caller_name, normalized, user::stdout_handle);

			write_handle_result(emulator, handle_out_address, static_cast<object_manager_t::handle_type>(user::stdout_handle));
			write_io_status(emulator, io_status_block_address, 0, file_opened);
			write_nt_success(emulator);

			return;
		}

		if (upper == "CONIN$" || upper.ends_with("/CONIN$"))
		{
			THREAD_LOG("{}: console input device '{}' -> pseudo-handle 0x{:X}",
				caller_name, normalized, user::stdin_handle);

			write_handle_result(emulator, handle_out_address, static_cast<object_manager_t::handle_type>(user::stdin_handle));
			write_io_status(emulator, io_status_block_address, 0, file_opened);
			write_nt_success(emulator);

			return;
		}

		if (upper == "NUL" || upper.ends_with("/NUL"))
		{
			THREAD_LOG("{}: NUL device '{}' -> pseudo-handle 0x{:X}",
				caller_name, normalized, user::nul_handle);

			write_handle_result(emulator, handle_out_address, static_cast<object_manager_t::handle_type>(user::nul_handle));
			write_io_status(emulator, io_status_block_address, 0, file_opened);
			write_nt_success(emulator);

			return;
		}
	}

	const auto& filesystem = kernel::filesystem;

	const bool want_directory = (create_options & file_directory_file) != 0;
	const bool want_non_directory = (create_options & file_non_directory_file) != 0;

	std::shared_ptr<file_t> file;
	std::uint64_t information = 0;

	switch (create_disposition)
	{
	case file_open:
	{
		file = filesystem->open_at(normalized);

		if (file && want_non_directory && file->is_directory())
		{
			THREAD_WARN_LOG("{}: '{}' is a directory but caller requested non-directory", caller_name, normalized);

			write_io_status(emulator, io_status_block_address, static_cast<std::int32_t>(status_file_is_a_directory), 0);
			write_nt_status(emulator, status_file_is_a_directory);

			return;
		}

		if (file && want_directory && !file->is_directory())
		{
			THREAD_WARN_LOG("{}: '{}' is a file but caller requested directory", caller_name, normalized);

			write_io_status(emulator, io_status_block_address, static_cast<std::int32_t>(status_not_a_directory), 0);
			write_nt_status(emulator, status_not_a_directory);

			return;
		}

		if (!file)
		{
			if (filesystem->directory_exists(normalized))
			{
				file = filesystem->open_directory_at(normalized);
			}
		}

		if (!file)
		{
			THREAD_WARN_LOG("{}: file not found '{}'", caller_name, normalized);

			write_io_status(emulator, io_status_block_address, static_cast<std::int32_t>(status_object_name_not_found), 0);
			write_nt_status(emulator, status_object_name_not_found);

			return;
		}

		information = file_opened;

		break;
	}
	case file_create:
	{
		if (filesystem->exists(normalized))
		{
			file = filesystem->open_at(normalized);
			information = file_opened;

			THREAD_LOG("{}: file already exists '{}', opening existing", caller_name, normalized);

			break;
		}

		file = want_directory ? filesystem->create_directory_at(normalized) : filesystem->create_at(normalized);
		information = file_created;

		break;
	}
	case file_open_if:
	{
		file = filesystem->open_at(normalized);

		if (file)
		{
			if (want_non_directory && file->is_directory())
			{
				THREAD_WARN_LOG("{}: '{}' is a directory but caller requested non-directory", caller_name, normalized);

				write_io_status(emulator, io_status_block_address, static_cast<std::int32_t>(status_file_is_a_directory), 0);
				write_nt_status(emulator, status_file_is_a_directory);

				return;
			}

			if (want_directory && !file->is_directory())
			{
				THREAD_WARN_LOG("{}: '{}' is a file but caller requested directory", caller_name, normalized);

				write_io_status(emulator, io_status_block_address, static_cast<std::int32_t>(status_not_a_directory), 0);
				write_nt_status(emulator, status_not_a_directory);

				return;
			}

			information = file_opened;
		}
		else if (filesystem->directory_exists(normalized))
		{
			file = filesystem->open_directory_at(normalized);
			information = file_opened;
		}
		else
		{
			file = want_directory ? filesystem->create_directory_at(normalized) : filesystem->create_at(normalized);
			information = file_created;
		}

		break;
	}
	case file_overwrite:
	{
		if (!filesystem->exists(normalized))
		{
			THREAD_WARN_LOG("{}: file not found for overwrite '{}'", caller_name, normalized);

			write_io_status(emulator, io_status_block_address, static_cast<std::int32_t>(status_object_name_not_found), 0);
			write_nt_status(emulator, status_object_name_not_found);

			return;
		}

		file = filesystem->create_at(normalized);
		information = file_opened;

		break;
	}
	case file_overwrite_if:
	{
		const bool existed = filesystem->exists(normalized);

		file = filesystem->create_at(normalized);
		information = existed ? file_opened : file_created;

		break;
	}
	case file_supersede:
	{
		file = filesystem->create_at(normalized);
		information = file_superseded;

		break;
	}
	default:
	{
		THREAD_WARN_LOG("{}: invalid create disposition 0x{:X}", caller_name, create_disposition);

		write_nt_status(emulator, status_invalid_parameter);

		return;
	}
	}

	if (!file)
	{
		THREAD_ERR_LOG("{}: failed to create/open file for '{}'", caller_name, normalized);

		write_io_status(emulator, io_status_block_address, static_cast<std::int32_t>(0xC0000001), 0);
		write_nt_status(emulator, 0xC0000001);

		return;
	}

	auto host_object = std::make_shared<file_object_t>(file, normalized);

	std::array<std::uint8_t, file_object_body_size> body{};
	const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size(), host_object);
	const auto handle_value = kernel::active_handle_table().create_handle(body_address, desired_access);

	THREAD_LOG("{}: handle 0x{:X} for '{}' (access=0x{:X}, info={}, *file_handle=0x{:X})",
		caller_name, handle_value, normalized, desired_access, information, handle_out_address);

	write_handle_result(emulator, handle_out_address, handle_value);
	write_io_status(emulator, io_status_block_address, 0, information);
	write_nt_success(emulator);
}

// NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
static void handle_open_file(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type file_handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes, emulator_t::address_type io_status_block,
	std::uint32_t share_access, std::uint32_t open_options)
{
	THREAD_LOG("NtOpenFile called (file_handle_out=0x{:X}, desired_access=0x{:X}, object_attributes=0x{:X}, io_status_block=0x{:X}, share_access=0x{:X}, open_options=0x{:X})",
		file_handle_out, desired_access, object_attributes, io_status_block, share_access, open_options);

	iop_create_file(emulator, file_handle_out, desired_access, object_attributes, io_status_block, file_open, open_options, "NtOpenFile");
}

// NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
static void handle_create_file(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type file_handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes, emulator_t::address_type io_status_block,
	std::uint64_t allocation_size, std::uint32_t file_attributes,
	std::uint32_t share_access, std::uint32_t create_disposition,
	std::uint32_t create_options, std::uint64_t ea_buffer, std::uint32_t ea_length)
{
	THREAD_LOG("NtCreateFile called (file_handle_out=0x{:X}, desired_access=0x{:X}, object_attributes=0x{:X}, io_status_block=0x{:X}, allocation_size=0x{:X}, file_attributes=0x{:X}, share_access=0x{:X}, create_disposition=0x{:X}, create_options=0x{:X}, ea_buffer=0x{:X}, ea_length=0x{:X})",
		file_handle_out, desired_access, object_attributes, io_status_block, allocation_size, file_attributes, share_access, create_disposition, create_options, ea_buffer, ea_length);

	iop_create_file(emulator, file_handle_out, desired_access, object_attributes, io_status_block, create_disposition, create_options, "NtCreateFile");
}

// IoCreateFileEx(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG Disposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength, CREATE_FILE_TYPE CreateFileType, PVOID InternalParameters, ULONG Options, PVOID DriverContext)
static void handle_io_create_file_ex(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type file_handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes, emulator_t::address_type io_status_block,
	std::uint64_t allocation_size, std::uint32_t file_attributes,
	std::uint32_t share_access, std::uint32_t disposition,
	std::uint32_t create_options, std::uint64_t ea_buffer, std::uint32_t ea_length,
	std::uint32_t create_file_type, std::uint64_t internal_parameters,
	std::uint32_t options, std::uint64_t driver_context)
{
	THREAD_LOG("IoCreateFileEx called (file_handle_out=0x{:X}, desired_access=0x{:X}, object_attributes=0x{:X}, io_status_block=0x{:X}, allocation_size=0x{:X}, file_attributes=0x{:X}, share_access=0x{:X}, disposition=0x{:X}, create_options=0x{:X}, ea_buffer=0x{:X}, ea_length=0x{:X}, create_file_type=0x{:X}, internal_parameters=0x{:X}, options=0x{:X}, driver_context=0x{:X})",
		file_handle_out, desired_access, object_attributes, io_status_block, allocation_size, file_attributes, share_access, disposition, create_options, ea_buffer, ea_length, create_file_type, internal_parameters, options, driver_context);

	iop_create_file(emulator, file_handle_out, desired_access, object_attributes, io_status_block, disposition, create_options, "IoCreateFileEx");
}

// NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
static void handle_write_file(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t file_handle, emulator_t::address_type event,
	emulator_t::address_type apc_routine, emulator_t::address_type apc_context,
	emulator_t::address_type io_status_block, emulator_t::address_type buffer_address,
	std::uint32_t length, emulator_t::address_type byte_offset_ptr,
	emulator_t::address_type key_ptr)
{
	THREAD_LOG("NtWriteFile called (handle=0x{:X}, event=0x{:X}, apc_routine=0x{:X}, apc_context=0x{:X}, io_status_block=0x{:X}, buffer=0x{:X}, length=0x{:X}, byte_offset_ptr=0x{:X}, key_ptr=0x{:X})",
		file_handle, event, apc_routine, apc_context, io_status_block, buffer_address, length, byte_offset_ptr, key_ptr);

	if (file_handle == user::stdout_handle || file_handle == user::stderr_handle)
	{
		if (buffer_address && length)
		{
			std::vector<std::uint8_t> buffer(length);
			emulator_err_t error = emulator->read_virtual_memory(buffer_address, buffer.data(), length);
			error.throw_if("read write buffer from guest");

			std::string_view text(reinterpret_cast<const char*>(buffer.data()), length);
			if (!text.empty() && text.back() == '\n')
			{
				text.remove_suffix(1);
			}
			THREAD_LOG("guest stdout: '{}'", text);
		}

		write_io_status(emulator, io_status_block, 0, length);
		write_nt_success(emulator);

		return;
	}

	if (file_handle == user::nul_handle)
	{
		write_io_status(emulator, io_status_block, 0, length);
		write_nt_success(emulator);

		return;
	}

	const auto entry = kernel::active_handle_table().lookup_handle(file_handle);

	if (!entry)
	{
		THREAD_WARN_LOG("NtWriteFile: invalid handle 0x{:X}", file_handle);

		write_io_status(emulator, io_status_block, static_cast<std::int32_t>(0xC0000008), 0);
		write_nt_status(emulator, 0xC0000008);

		return;
	}

	if (!(entry->access & (object_manager_t::generic_write | object_manager_t::file_write_data | object_manager_t::file_append_data | object_manager_t::generic_all)))
	{
		THREAD_WARN_LOG("NtWriteFile: handle 0x{:X} not writable", file_handle);

		write_io_status(emulator, io_status_block, static_cast<std::int32_t>(0xC0000022), 0);
		write_nt_status(emulator, 0xC0000022);

		return;
	}

	if (!buffer_address || !length)
	{
		THREAD_WARN_LOG("NtWriteFile: null buffer or zero length");

		write_io_status(emulator, io_status_block, static_cast<std::int32_t>(0xC000000D), 0);
		write_nt_status(emulator, 0xC000000D);

		return;
	}

	const auto host_object = kernel::active_handle_table().get_object_from_handle<file_object_t>(file_handle);

	if (!host_object || !host_object->file)
	{
		THREAD_ERR_LOG("NtWriteFile: handle 0x{:X} has no backing file", file_handle);

		write_io_status(emulator, io_status_block, static_cast<std::int32_t>(0xC0000008), 0);
		write_nt_status(emulator, 0xC0000008);

		return;
	}

	std::vector<std::uint8_t> buffer(length);

	emulator_err_t error = emulator->read_virtual_memory(buffer_address, buffer.data(), length);
	error.throw_if("read write buffer from guest");

	const auto write_span = std::span<const std::uint8_t>(buffer.data(), buffer.size());

	host_object->file->write(write_span);

	THREAD_LOG("NtWriteFile: wrote {} bytes to handle 0x{:X}", length, file_handle);

	write_io_status(emulator, io_status_block, 0, length);
	write_nt_success(emulator);
}

// NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
static void handle_read_file(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t file_handle, emulator_t::address_type event,
	emulator_t::address_type apc_routine, emulator_t::address_type apc_context,
	emulator_t::address_type io_status_block, emulator_t::address_type buffer_address,
	std::uint32_t length, emulator_t::address_type byte_offset_ptr,
	emulator_t::address_type key_ptr)
{
	THREAD_LOG("NtReadFile called (handle=0x{:X}, event=0x{:X}, apc_routine=0x{:X}, apc_context=0x{:X}, io_status_block=0x{:X}, buffer=0x{:X}, length=0x{:X}, byte_offset_ptr=0x{:X}, key_ptr=0x{:X})",
		file_handle, event, apc_routine, apc_context, io_status_block, buffer_address, length, byte_offset_ptr, key_ptr);

	if (user::is_console_handle(file_handle))
	{
		constexpr std::uint32_t status_end_of_file = 0xC0000011;
		write_io_status(emulator, io_status_block, static_cast<std::int32_t>(status_end_of_file), 0);
		write_nt_status(emulator, status_end_of_file);

		return;
	}

	const auto entry = kernel::active_handle_table().lookup_handle(file_handle);

	if (!entry)
	{
		THREAD_WARN_LOG("NtReadFile: invalid handle 0x{:X}", file_handle);

		write_io_status(emulator, io_status_block, static_cast<std::int32_t>(0xC0000008), 0);
		write_nt_status(emulator, 0xC0000008);

		return;
	}

	if (!(entry->access & (object_manager_t::generic_read | object_manager_t::file_read_data | object_manager_t::generic_all)))
	{
		THREAD_WARN_LOG("NtReadFile: handle 0x{:X} not readable", file_handle);

		write_io_status(emulator, io_status_block, static_cast<std::int32_t>(0xC0000022), 0);
		write_nt_status(emulator, 0xC0000022);

		return;
	}

	if (!buffer_address || !length)
	{
		THREAD_WARN_LOG("NtReadFile: null buffer or zero length");

		write_io_status(emulator, io_status_block, static_cast<std::int32_t>(0xC000000D), 0);
		write_nt_status(emulator, 0xC000000D);

		return;
	}

	const auto host_object = kernel::active_handle_table().get_object_from_handle<file_object_t>(file_handle);

	if (!host_object || !host_object->file)
	{
		THREAD_ERR_LOG("NtReadFile: handle 0x{:X} has no backing file", file_handle);

		write_io_status(emulator, io_status_block, static_cast<std::int32_t>(0xC0000008), 0);
		write_nt_status(emulator, 0xC0000008);

		return;
	}

	const auto file_data = host_object->file->read();
	const auto file_size = file_data.size();

	std::uint64_t offset = 0;

	if (byte_offset_ptr)
	{
		std::int64_t byte_offset = 0;
		emulator_err_t error = emulator->read_virtual_memory(byte_offset_ptr, &byte_offset, sizeof(byte_offset));
		error.throw_if("read byte offset");

		offset = static_cast<std::uint64_t>(byte_offset);
	}

	if (offset >= file_size)
	{
		constexpr std::uint32_t status_end_of_file = 0xC0000011;

		THREAD_LOG("NtReadFile: read past end of file (offset=0x{:X}, file_size=0x{:X})", offset, file_size);

		write_io_status(emulator, io_status_block, static_cast<std::int32_t>(status_end_of_file), 0);
		write_nt_status(emulator, status_end_of_file);

		return;
	}

	const auto available = file_size - offset;
	const auto bytes_to_read = static_cast<std::uint32_t>(std::min(static_cast<std::uint64_t>(length), available));

	emulator_err_t error = emulator->write_virtual_memory(buffer_address, file_data.data() + offset, bytes_to_read);
	error.throw_if("write read buffer to guest");

	THREAD_LOG("NtReadFile: read {} bytes from handle 0x{:X} at offset 0x{:X}", bytes_to_read, file_handle, offset);

	write_io_status(emulator, io_status_block, 0, bytes_to_read);
	write_nt_success(emulator);
}

// ZwFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock)
static void handle_flush_buffers_file(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t file_handle, emulator_t::address_type io_status_block)
{
	THREAD_LOG("ZwFlushBuffersFile called (handle=0x{:X}, io_status_block=0x{:X})", file_handle, io_status_block);

	write_io_status(emulator, io_status_block, 0, 0);
	write_nt_success(emulator);
}

constexpr std::uint32_t file_standard_information_class = 5;
constexpr std::size_t file_standard_information_size = 0x18;

// NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
static void handle_query_information_file(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t file_handle, emulator_t::address_type io_status_block,
	emulator_t::address_type file_information, std::uint32_t length,
	std::uint32_t information_class)
{
	THREAD_LOG("NtQueryInformationFile called (handle=0x{:X}, class={}, buffer=0x{:X}, length=0x{:X})",
		file_handle, information_class, file_information, length);

	if (information_class == file_standard_information_class)
	{
		if (length < file_standard_information_size)
		{
			constexpr std::uint32_t status_buffer_too_small = 0xC0000023;
			write_nt_status(emulator, status_buffer_too_small);
			return;
		}

		const auto host_object = kernel::active_handle_table().get_object_from_handle<file_object_t>(file_handle);
		const bool is_directory = host_object && host_object->file && host_object->file->is_directory();
		const std::int64_t file_size = (host_object && host_object->file && !is_directory) ? static_cast<std::int64_t>(host_object->file->size()) : 0;

		struct
		{
			std::int64_t allocation_size;
			std::int64_t end_of_file;
			std::uint32_t number_of_links;
			std::uint8_t delete_pending;
			std::uint8_t directory;
			std::uint16_t padding;
		} standard_info = { };

		standard_info.allocation_size = (file_size + 0xFFF) & ~0xFFFll;
		standard_info.end_of_file = file_size;
		standard_info.number_of_links = 1;
		standard_info.directory = is_directory ? 1 : 0;

		emulator_err_t error = emulator->write_virtual_memory(file_information, &standard_info, sizeof(standard_info));
		error.throw_if("NtQueryInformationFile: write FileStandardInformation");

		write_io_status(emulator, io_status_block, 0, file_standard_information_size);
		write_nt_success(emulator);
		return;
	}

	write_io_status(emulator, io_status_block, 0, 0);
	write_nt_success(emulator);
}

// IoQueryFileInformation(PFILE_OBJECT FileObject, FILE_INFORMATION_CLASS FileInformationClass, ULONG Length, PVOID FileInformation, PULONG ReturnedLength)
static void handle_io_query_file_information(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type file_object, std::uint32_t information_class,
	std::uint32_t length, emulator_t::address_type file_information,
	emulator_t::address_type returned_length_address)
{
	THREAD_LOG("IoQueryFileInformation called (file_object=0x{:X}, class={}, length=0x{:X}, buffer=0x{:X})",
		file_object, information_class, length, file_information);

	constexpr std::uint32_t standard_class = 5;
	constexpr std::size_t standard_size = 0x18;

	if (information_class == standard_class && length >= standard_size)
	{
		struct
		{
			std::int64_t allocation_size;
			std::int64_t end_of_file;
			std::uint32_t number_of_links;
			std::uint8_t delete_pending;
			std::uint8_t directory;
			std::uint16_t padding;
		} standard_info = { };

		standard_info.number_of_links = 1;

		emulator_err_t error = emulator->write_virtual_memory(file_information, &standard_info, sizeof(standard_info));
		error.throw_if("IoQueryFileInformation: write FileStandardInformation");

		if (returned_length_address)
		{
			constexpr std::uint32_t returned = static_cast<std::uint32_t>(standard_size);
			error = emulator->write_virtual_memory(returned_length_address, &returned, sizeof(returned));
			error.throw_if("IoQueryFileInformation: write ReturnedLength");
		}

		write_nt_success(emulator);
		return;
	}

	if (returned_length_address)
	{
		constexpr std::uint32_t zero = 0;
		emulator_err_t error = emulator->write_virtual_memory(returned_length_address, &zero, sizeof(zero));
		error.throw_if("IoQueryFileInformation: write zero ReturnedLength");
	}

	write_nt_success(emulator);
}

// IoQueryFileDosDeviceName(PFILE_OBJECT FileObject, POBJECT_NAME_INFORMATION* ObjectNameInformation)
static void handle_io_query_file_dos_device_name(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type file_object, emulator_t::address_type name_info_out)
{
	THREAD_LOG("IoQueryFileDosDeviceName called (file_object=0x{:X}, name_info_out=0x{:X})",
		file_object, name_info_out);

	// OBJECT_NAME_INFORMATION is { UNICODE_STRING Name; } followed by the string buffer
	const std::wstring fake_path = L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntoskrnl.exe";
	const auto byte_len = static_cast<std::uint16_t>(fake_path.size() * sizeof(wchar_t));

	// allocate: sizeof(UNICODE_STRING) = 16 bytes, then the wchar buffer
	const auto total_size = static_cast<std::uint64_t>(sizeof(UNICODE_STRING) + byte_len + sizeof(wchar_t));
	const auto alloc = emulator->heap_allocate(total_size, prot_read_write, true);
	auto error = alloc.error_or({});
	error.throw_if("IoQueryFileDosDeviceName: allocate name info");

	const auto alloc_addr = *alloc;
	const auto buffer_addr = alloc_addr + sizeof(UNICODE_STRING);

	UNICODE_STRING us{};
	us.Length = byte_len;
	us.MaximumLength = byte_len + sizeof(wchar_t);
	us.Buffer = reinterpret_cast<wchar_t*>(buffer_addr);

	error = emulator->write_virtual_memory(alloc_addr, &us, sizeof(us));
	error.throw_if("IoQueryFileDosDeviceName: write UNICODE_STRING");

	error = emulator->write_virtual_memory(buffer_addr, fake_path.data(), byte_len);
	error.throw_if("IoQueryFileDosDeviceName: write name buffer");

	// write null terminator
	const wchar_t null_term = L'\0';
	error = emulator->write_virtual_memory(buffer_addr + byte_len, &null_term, sizeof(null_term));
	error.throw_if("IoQueryFileDosDeviceName: write null terminator");

	// write the pointer to the allocated OBJECT_NAME_INFORMATION
	error = emulator->write_virtual_memory(name_info_out, &alloc_addr, sizeof(alloc_addr));
	error.throw_if("IoQueryFileDosDeviceName: write output pointer");

	write_nt_success(emulator);
}

// NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
static void handle_device_io_control_file(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t file_handle, emulator_t::address_type event,
	emulator_t::address_type apc_routine, emulator_t::address_type apc_context,
	emulator_t::address_type io_status_block, std::uint32_t io_control_code,
	emulator_t::address_type input_buffer, std::uint32_t input_buffer_length,
	emulator_t::address_type output_buffer, std::uint32_t output_buffer_length)
{
	THREAD_LOG("NtDeviceIoControlFile called (handle=0x{:X}, ioctl=0x{:X}, input=0x{:X}, input_len=0x{:X}, output=0x{:X}, output_len=0x{:X})",
		file_handle, io_control_code, input_buffer, input_buffer_length, output_buffer, output_buffer_length);

	write_io_status(emulator, io_status_block, 0, 0);
	write_nt_success(emulator);
}

// NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan)
static void handle_query_directory_file(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t file_handle, emulator_t::address_type event,
	emulator_t::address_type apc_routine, emulator_t::address_type apc_context,
	emulator_t::address_type io_status_block, emulator_t::address_type file_information,
	std::uint32_t length, std::uint32_t information_class,
	std::uint8_t return_single_entry, emulator_t::address_type file_name_ptr,
	std::uint8_t restart_scan)
{
	std::string search_pattern;

	if (file_name_ptr)
	{
		const auto file_name = emulator_object_t<UNICODE_STRING>::view_at(emulator, file_name_ptr).read();
		const auto buffer_address = reinterpret_cast<emulator_t::address_type>(file_name.Buffer);

		if (buffer_address && file_name.Length)
		{
			search_pattern = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
		}
	}

	const auto host_object = kernel::active_handle_table().get_object_from_handle<file_object_t>(file_handle);
	const std::string directory_path = host_object ? host_object->path : std::string{};

	THREAD_LOG("NtQueryDirectoryFile called (handle=0x{:X}, event=0x{:X}, apc_routine=0x{:X}, apc_context=0x{:X}, io_status_block=0x{:X}, buffer=0x{:X}, length=0x{:X}, class={}, return_single_entry={}, file_name='{}', restart_scan={}, dir='{}')",
		file_handle, event, apc_routine, apc_context, io_status_block, file_information, length, information_class, return_single_entry, search_pattern, restart_scan, directory_path);

	const auto directory_file = host_object ? host_object->file : nullptr;

	if (!host_object || !directory_file || !directory_file->is_directory())
	{
		THREAD_WARN_LOG("NtQueryDirectoryFile: handle 0x{:X} is not a directory", file_handle);

		write_io_status(emulator, io_status_block, static_cast<std::int32_t>(status_invalid_parameter), 0);
		write_nt_status(emulator, status_invalid_parameter);

		return;
	}

	if (restart_scan)
	{
		host_object->directory_offset = 0;
	}

	const auto entries = kernel::filesystem->list_directory(host_object->path);
	const std::size_t start = host_object->directory_offset;

	if (start >= entries.size())
	{
		const std::uint32_t status = (start == 0) ? status_no_such_file : status_no_more_files;

		write_io_status(emulator, io_status_block, static_cast<std::int32_t>(status), 0);
		write_nt_status(emulator, status);

		return;
	}

	constexpr std::uint32_t file_attribute_directory = 0x10;
	constexpr std::uint32_t file_attribute_normal = 0x80;
	constexpr std::size_t header_size = sizeof(file_directory_information_t);

	std::uint64_t total_written = 0;
	std::uint64_t last_entry_offset = 0;
	std::size_t produced = 0;
	std::size_t index = start;

	for (; index < entries.size(); ++index)
	{
		const auto& dir_entry = entries[index];
		const auto wide_name = util::widen_string(dir_entry.name);
		const std::size_t name_bytes = wide_name.size() * sizeof(wchar_t);
		const std::size_t entry_size = header_size + name_bytes;
		const std::size_t aligned_size = (entry_size + 7) & ~static_cast<std::size_t>(7);

		if (total_written + entry_size > length)
		{
			if (produced == 0)
			{
				write_io_status(emulator, io_status_block, static_cast<std::int32_t>(status_buffer_overflow), 0);
				write_nt_status(emulator, status_buffer_overflow);

				return;
			}

			break;
		}

		file_directory_information_t header = { };
		header.next_entry_offset = static_cast<std::uint32_t>(aligned_size);
		header.end_of_file = dir_entry.is_directory ? 0 : static_cast<std::int64_t>(dir_entry.size);
		header.allocation_size = dir_entry.is_directory ? 0 : ((static_cast<std::int64_t>(dir_entry.size) + 0xFFF) & ~static_cast<std::int64_t>(0xFFF));
		header.file_attributes = dir_entry.is_directory ? file_attribute_directory : file_attribute_normal;
		header.file_name_length = static_cast<std::uint32_t>(name_bytes);

		const auto entry_address = file_information + total_written;

		emulator_err_t error = emulator->write_virtual_memory(entry_address, &header, sizeof(header));
		error.throw_if("write directory entry header");

		if (name_bytes)
		{
			error = emulator->write_virtual_memory(entry_address + header_size, wide_name.data(), name_bytes);
			error.throw_if("write directory entry name");
		}

		last_entry_offset = total_written;
		total_written += aligned_size;
		++produced;

		if (return_single_entry)
		{
			++index;

			break;
		}
	}

	const std::uint32_t terminator = 0;
	emulator_err_t error = emulator->write_virtual_memory(file_information + last_entry_offset, &terminator, sizeof(terminator));
	error.throw_if("terminate directory listing");

	host_object->directory_offset = index;

	THREAD_LOG("NtQueryDirectoryFile: returned {} entries ({} bytes) from '{}' (offset now {})",
		produced, total_written, host_object->path, host_object->directory_offset);

	write_io_status(emulator, io_status_block, 0, total_written);
	write_nt_success(emulator);
}

// NtQueryFullAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_NETWORK_OPEN_INFORMATION FileInformation)
static void handle_query_full_attributes_file(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type object_attributes_address, emulator_t::address_type file_information)
{
	std::string normalized;

	if (!resolve_object_name(emulator, object_attributes_address, normalized, "NtQueryFullAttributesFile"))
	{
		return;
	}

	const auto& filesystem = kernel::filesystem;
	const auto file = filesystem->open_at(normalized);

	if (!file)
	{
		THREAD_LOG("NtQueryFullAttributesFile: file not found '{}'", normalized);

		write_nt_status(emulator, status_object_name_not_found);
		return;
	}

	const auto file_size = static_cast<std::int64_t>(file->read().size());

	struct FILE_NETWORK_OPEN_INFORMATION
	{
		std::int64_t creation_time;
		std::int64_t last_access_time;
		std::int64_t last_write_time;
		std::int64_t change_time;
		std::int64_t allocation_size;
		std::int64_t end_of_file;
		std::uint32_t file_attributes;
		std::uint32_t reserved;
	};

	constexpr std::int64_t default_time = 132800000000000000LL;

	FILE_NETWORK_OPEN_INFORMATION info = { };
	info.creation_time = default_time;
	info.last_access_time = default_time;
	info.last_write_time = default_time;
	info.change_time = default_time;
	info.allocation_size = (file_size + 0xFFF) & ~0xFFFLL;
	info.end_of_file = file_size;
	info.file_attributes = file->is_directory() ? 0x10 : 0x20;

	emulator_err_t error = emulator->write_virtual_memory(file_information, &info, sizeof(info));
	error.throw_if("NtQueryFullAttributesFile: write FILE_NETWORK_OPEN_INFORMATION");

	THREAD_LOG("NtQueryFullAttributesFile: '{}' size=0x{:X} attrs=0x{:X}",
		normalized, file_size, info.file_attributes);

	write_nt_success(emulator);
}

// NtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, ULONG Length, FS_INFORMATION_CLASS FsInformationClass)
static void handle_query_volume_information_file(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t file_handle, emulator_t::address_type io_status_block,
	emulator_t::address_type fs_information, std::uint32_t length,
	std::uint32_t fs_info_class)
{
	THREAD_LOG("NtQueryVolumeInformationFile called (handle=0x{:X}, io_status=0x{:X}, buf=0x{:X}, len=0x{:X}, class=0x{:X})",
		file_handle, io_status_block, fs_information, length, fs_info_class);

	constexpr std::uint32_t file_fs_device_information = 4;
	constexpr std::uint32_t file_fs_attribute_information = 5;

	if (fs_info_class == file_fs_device_information && length >= 8)
	{
		struct
		{
			std::uint32_t device_type;
			std::uint32_t characteristics;
		} device_info{};

		if (user::is_console_handle(file_handle))
		{
			device_info.device_type = 0x50;
			device_info.characteristics = 0x20000;
		}
		else
		{
			device_info.device_type = 0x7;
			device_info.characteristics = 0x20;
		}

		emulator_err_t error = emulator->write_virtual_memory(fs_information, &device_info, sizeof(device_info));
		error.throw_if("NtQueryVolumeInformationFile: write device info");

		write_io_status(emulator, io_status_block, 0, sizeof(device_info));
		write_nt_success(emulator);

		return;
	}

	if (fs_info_class == file_fs_attribute_information && length >= 16)
	{
		const wchar_t fs_name[] = L"NTFS";
		const auto name_bytes = static_cast<std::uint32_t>(4 * sizeof(wchar_t));

		struct
		{
			std::uint32_t attributes;
			std::int32_t max_component_length;
			std::uint32_t name_length;
		} attr_header{};

		attr_header.attributes = 0x000700FF;
		attr_header.max_component_length = 255;
		attr_header.name_length = name_bytes;

		emulator_err_t error = emulator->write_virtual_memory(fs_information, &attr_header, sizeof(attr_header));
		error.throw_if("NtQueryVolumeInformationFile: write attr header");

		const auto name_offset = fs_information + sizeof(attr_header);
		error = emulator->write_virtual_memory(name_offset, fs_name, name_bytes);
		error.throw_if("NtQueryVolumeInformationFile: write fs name");

		const auto total = static_cast<std::uint32_t>(sizeof(attr_header) + name_bytes);

		write_io_status(emulator, io_status_block, 0, total);
		write_nt_success(emulator);

		return;
	}

	THREAD_WARN_LOG("NtQueryVolumeInformationFile: unsupported class 0x{:X}, returning STATUS_SUCCESS", fs_info_class);

	write_io_status(emulator, io_status_block, 0, 0);
	write_nt_success(emulator);
}

void redirect_ntoskrnl_file_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_open_file>(emulator, mapped_image, "NtOpenFile");

	redirect_handler<handle_create_file>(emulator, mapped_image, "NtCreateFile");
	redirect_handler<handle_create_file>(emulator, mapped_image, "ZwCreateFile");

	redirect_handler<handle_io_create_file_ex>(emulator, mapped_image, "IoCreateFileEx");

	redirect_handler<handle_write_file>(emulator, mapped_image, "NtWriteFile");
	redirect_handler<handle_write_file>(emulator, mapped_image, "ZwWriteFile");

	redirect_handler<handle_read_file>(emulator, mapped_image, "NtReadFile");
	redirect_handler<handle_read_file>(emulator, mapped_image, "ZwReadFile");

	redirect_handler<handle_flush_buffers_file>(emulator, mapped_image, "ZwFlushBuffersFile");

	redirect_handler<handle_query_information_file>(emulator, mapped_image, "NtQueryInformationFile");
	redirect_handler<handle_query_information_file>(emulator, mapped_image, "ZwQueryInformationFile");

	redirect_handler<handle_io_query_file_information>(emulator, mapped_image, "IoQueryFileInformation");

	redirect_handler<handle_io_query_file_dos_device_name>(emulator, mapped_image, "IoQueryFileDosDeviceName");

	redirect_handler<handle_device_io_control_file>(emulator, mapped_image, "NtDeviceIoControlFile");
	redirect_handler<handle_device_io_control_file>(emulator, mapped_image, "ZwDeviceIoControlFile");
	redirect_handler<handle_device_io_control_file>(emulator, mapped_image, "NtFsControlFile");
	redirect_handler<handle_device_io_control_file>(emulator, mapped_image, "ZwFsControlFile");

	redirect_handler<handle_query_directory_file>(emulator, mapped_image, "NtQueryDirectoryFile");
	redirect_handler<handle_query_directory_file>(emulator, mapped_image, "ZwQueryDirectoryFile");

	redirect_handler<handle_query_full_attributes_file>(emulator, mapped_image, "NtQueryFullAttributesFile");

	redirect_handler<handle_query_volume_information_file>(emulator, mapped_image, "NtQueryVolumeInformationFile");
}
