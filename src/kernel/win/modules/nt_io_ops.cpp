#include "nt_io_ops.hpp"
#include "../win_kernel.hpp"
#include "../filesystem.hpp"
#include "../mdl.hpp"
#include "../objects.hpp"
#include "../pool.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <algorithm>
#include <cstring>
#include <functional>
#include <string_view>
#include <vector>

namespace
{

// CreateDisposition, and what IO_STATUS_BLOCK::Information reports for each.
enum create_disposition : std::uint32_t
{
	file_supersede    = 0,
	file_open         = 1,
	file_create       = 2,
	file_open_if      = 3,
	file_overwrite    = 4,
	file_overwrite_if = 5,
};

enum create_result : std::uint64_t
{
	file_superseded = 0,
	file_opened     = 1,
	file_created    = 2,
	file_overwritten = 3,
};

// FILE_INFORMATION_CLASS, the ones answerable about a file in this store.
enum file_information_class : std::uint32_t
{
	file_directory_information      = 1,
	file_full_directory_information = 2,
	file_both_directory_information = 3,
	file_basic_information          = 4,
	file_standard_information       = 5,
	file_internal_information       = 6,
	file_position_information       = 14,
	file_network_open_information   = 34,
};

// FS_INFORMATION_CLASS and the device type it reports.
constexpr std::uint32_t file_fs_device_information = 4;
constexpr std::uint32_t file_device_disk = 0x07;

// What GetFileType turns into FILE_TYPE_CHAR, and with it what the crt decides
// a stream is: a stream on a disk file is buffered until something flushes it,
// and nothing flushes an exe that returns straight out of its entry point.
constexpr std::uint32_t file_device_console = 0x50;

// FILE_ATTRIBUTE_*.
constexpr std::uint32_t file_attribute_normal = 0x80;
constexpr std::uint32_t file_attribute_directory = 0x10;

// CreateOptions, the two that say what kind of thing the caller expects.
constexpr std::uint32_t file_directory_file = 0x00000001;
constexpr std::uint32_t file_non_directory_file = 0x00000040;

// ByteOffset sentinels: either says to carry on from where the file object is.
constexpr std::int64_t file_use_file_pointer_position = -2;
constexpr std::int64_t file_write_to_end_of_file = -1;

#pragma pack(push, 4)
struct file_basic_information_t
{
	std::int64_t  creation_time;
	std::int64_t  last_access_time;
	std::int64_t  last_write_time;
	std::int64_t  change_time;
	std::uint32_t file_attributes;
	std::uint32_t padding;
};

struct file_standard_information_t
{
	std::int64_t  allocation_size;
	std::int64_t  end_of_file;
	std::uint32_t number_of_links;
	std::uint8_t  delete_pending;
	std::uint8_t  directory;
	std::uint16_t padding;
};

struct file_network_open_information_t
{
	std::int64_t  creation_time;
	std::int64_t  last_access_time;
	std::int64_t  last_write_time;
	std::int64_t  change_time;
	std::int64_t  allocation_size;
	std::int64_t  end_of_file;
	std::uint32_t file_attributes;
	std::uint32_t padding;
};

struct file_directory_information_t
{
	std::uint32_t next_entry_offset;
	std::uint32_t file_index;
	std::int64_t  creation_time;
	std::int64_t  last_access_time;
	std::int64_t  last_write_time;
	std::int64_t  change_time;
	std::int64_t  end_of_file;
	std::int64_t  allocation_size;
	std::uint32_t file_attributes;
	std::uint32_t file_name_length;
};

struct file_fs_device_information_t
{
	std::uint32_t device_type;
	std::uint32_t characteristics;
};
#pragma pack(pop)

static_assert(sizeof(file_basic_information_t) == 0x28);
static_assert(sizeof(file_standard_information_t) == 0x18);
static_assert(sizeof(file_network_open_information_t) == 0x38);
static_assert(sizeof(file_directory_information_t) == 0x40);

// The path an OBJECT_ATTRIBUTES names, in the form the store keeps.
std::string object_path(vcpu& cpu, const emu_object<_OBJECT_ATTRIBUTES>& object_attributes)
{
	auto& space = *cpu.curr_addr_space();

	const emu_object<_UNICODE_STRING> name(space, object_attributes
		? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
		: 0);

	return win_filesystem::normalize(narrow_wstring(win::read_unicode_string(name)));
}

// Where a read or write starts. A null pointer or either sentinel means the
// position the file object is already at.
std::uint64_t file_offset(const emu_object<std::int64_t>& byte_offset,
	const std::uint64_t position)
{
	if (!byte_offset)
		return position;

	const auto value = byte_offset.read();

	if (value == file_use_file_pointer_position || value == file_write_to_end_of_file)
		return position;

	return value < 0 ? position : static_cast<std::uint64_t>(value);
}

struct open_result
{
	NTSTATUS status = STATUS_SUCCESS;
	std::uint64_t information = 0;
};

open_result write_file_information(addr_space& space, const file_host& host,
	const std::uint32_t info_class, const addr_t buffer, const std::uint32_t length)
{
	const auto size = static_cast<std::int64_t>(host.file->size());

	switch (info_class)
	{
	case file_standard_information:
	{
		if (length < sizeof(file_standard_information_t))
			return {STATUS_INFO_LENGTH_MISMATCH, 0};

		file_standard_information_t info{};
		info.allocation_size = size;
		info.end_of_file = size;
		info.number_of_links = 1;

		emu_object<file_standard_information_t>(space, buffer).write(info);

		return {STATUS_SUCCESS, sizeof(info)};
	}

	case file_basic_information:
	{
		if (length < sizeof(file_basic_information_t))
			return {STATUS_INFO_LENGTH_MISMATCH, 0};

		file_basic_information_t info{};
		info.file_attributes = file_attribute_normal;

		emu_object<file_basic_information_t>(space, buffer).write(info);

		return {STATUS_SUCCESS, sizeof(info)};
	}

	case file_position_information:
	{
		if (length < sizeof(std::int64_t))
			return {STATUS_INFO_LENGTH_MISMATCH, 0};

		emu_object<std::int64_t>(space, buffer)
			.write(static_cast<std::int64_t>(host.position));

		return {STATUS_SUCCESS, sizeof(std::int64_t)};
	}

	case file_internal_information:
	{
		// The file id, which only has to be stable and unique. The address of
		// the host object is both.
		if (length < sizeof(std::int64_t))
			return {STATUS_INFO_LENGTH_MISMATCH, 0};

		emu_object<std::int64_t>(space, buffer)
			.write(static_cast<std::int64_t>(std::hash<std::string>{}(host.path)));

		return {STATUS_SUCCESS, sizeof(std::int64_t)};
	}

	default:
		return {STATUS_INVALID_INFO_CLASS, 0};
	}
}

// What every create path comes down to: find or make the file, and say which of
// the two happened. The disposition is the whole of the decision.
open_result open_file(win_kernel_state& state, const std::string& path,
	const std::uint32_t disposition, const std::uint32_t create_options,
	emu_object<std::uint64_t> file_handle)
{
	if (path.empty())
		return { STATUS_OBJECT_NAME_INVALID, 0 };

	const bool is_directory = state.fs.dir_exists(path);
	const bool existed = state.fs.exists(path) || is_directory;

	// A caller that said which of the two it wanted gets told when it is the
	// other, rather than a handle it will misuse.
	if (existed && is_directory && (create_options & file_non_directory_file))
		return { STATUS_FILE_IS_A_DIRECTORY, 0 };

	if (existed && !is_directory && (create_options & file_directory_file))
		return { STATUS_NOT_A_DIRECTORY, 0 };

	// A directory has no contents to open, only entries to enumerate, so the
	// file object behind one is empty and the path is what makes it useful.
	if (is_directory)
	{
		auto host = std::make_shared<file_host>();
		host->file = std::make_shared<win_file>();
		host->path = path;

		const std::uint8_t body[sizeof(addr_t)] = {};
		const auto addr = state.objs.create_object(0, body, sizeof(body),
			std::move(host), prot_rw | prot_supervisor);

		if (!addr)
			return { STATUS_INSUFFICIENT_RESOURCES, 0 };

		if (file_handle)
			file_handle.write(state.sys_proc->handle_table().create_handle(addr, 0));

		return { STATUS_SUCCESS, file_opened };
	}

	std::shared_ptr<win_file> file;
	std::uint64_t information = 0;

	switch (disposition)
	{
	case file_open:
		if (!existed)
			return { STATUS_OBJECT_NAME_NOT_FOUND, 0 };
		file = state.fs.open(path);
		information = file_opened;
		break;

	case file_create:
		if (existed)
			return { STATUS_OBJECT_NAME_COLLISION, 0 };
		file = state.fs.create(path);
		information = file_created;
		break;

	case file_open_if:
		file = existed ? state.fs.open(path) : state.fs.create(path);
		information = existed ? file_opened : file_created;
		break;

	case file_overwrite:
		if (!existed)
			return { STATUS_OBJECT_NAME_NOT_FOUND, 0 };
		file = state.fs.create(path);
		information = file_overwritten;
		break;

	case file_supersede:
	case file_overwrite_if:
		file = state.fs.create(path);
		information = existed
			? (disposition == file_supersede ? file_superseded : file_overwritten)
			: file_created;
		break;

	default:
		return { STATUS_INVALID_PARAMETER, 0 };
	}

	if (!file)
		return { STATUS_UNSUCCESSFUL, 0 };

	auto host = std::make_shared<file_host>();
	host->file = std::move(file);
	host->path = path;

	// The body is opaque: a driver passes the handle back, and a file object
	// pointer only ever reaches the object manager.
	const std::uint8_t body[sizeof(addr_t)] = {};
	const auto addr = state.objs.create_object(0, body, sizeof(body),
		std::move(host), prot_rw | prot_supervisor);

	if (!addr)
		return { STATUS_INSUFFICIENT_RESOURCES, 0 };

	if (file_handle)
		file_handle.write(state.sys_proc->handle_table().create_handle(addr, 0));

	return { STATUS_SUCCESS, information };
}

// Both halves, because a caller that ignores the return value reads Status out
// of the block instead.
void write_status_block(emu_object<_IO_STATUS_BLOCK> block, const open_result& result)
{
	if (!block)
		return;

	_IO_STATUS_BLOCK status{};
	status.Status = static_cast<std::int32_t>(result.status);
	status.Information = result.information;

	block.write(status);
}

}

// The io manager beyond the device object: the descriptor lists a driver builds
// over its own buffers, and the file and namespace queries it makes about them.
void modules::register_ntoskrnl_io_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// IoAllocateMdl only describes the buffer; the page frame array behind the
	// header stays empty until MmProbeAndLockPages or MmBuildMdlForNonPagedPool
	// fills it, which is also true of the real one.
	state.redirect(mod, "IoAllocateMdl",
		[st](vcpu& cpu, const addr_t virtual_address, const std::uint32_t length,
			const bool secondary_buffer, const bool charge_quota,
			emu_object<_IRP> irp) -> addr_t
		{
			const auto size = mdl_size(virtual_address, length);
			const auto addr = st->pool.allocate(size, pool_tag("Mdl "), true);

			if (!addr)
			{
				THREAD_LOG_ERR("IoAllocateMdl: out of pool for {} bytes", size);
				return 0;
			}

			mdl_t mdl{};
			mdl.size = static_cast<std::int16_t>(size);
			mdl.start_va = mdl_page_base(virtual_address);
			mdl.byte_offset = static_cast<std::uint32_t>(mdl_page_offset(virtual_address));
			mdl.byte_count = length;

			emu_object<mdl_t>(*cpu.curr_addr_space(), addr).write(mdl);

			// A secondary buffer is chained onto the IRP behind the one already
			// there; the primary one is the IRP's own. Nothing dispatches IRPs
			// here, so neither link is made.
			if (irp)
				THREAD_LOG_WARN("IoAllocateMdl: not chaining onto irp 0x{:X} ({}), because "
					"nothing dispatches IRPs", irp.address(),
					secondary_buffer ? "secondary" : "primary");

			THREAD_LOG_INFO("IoAllocateMdl(va=0x{:X}, {} bytes, charge_quota={}) -> 0x{:X} "
				"({} page(s))", virtual_address, length, charge_quota, addr,
				mdl_page_count(virtual_address, length));

			return addr;
		});

	state.redirect(mod, "IoFreeMdl", [st](vcpu&, const addr_t mdl)
	{
		const auto freed = st->pool.free(mdl);

		if (!freed)
		{
			THREAD_LOG_ERR("IoFreeMdl: 0x{:X} was not allocated here", mdl);
			return;
		}

		THREAD_LOG_INFO("IoFreeMdl(0x{:X}): {} bytes", mdl, freed->size);
	});

	// The counterpart of IoCreateSymbolicLink, which has no namespace to put a
	// link in -- so there is none to take out either.
	state.redirect(mod, "IoDeleteSymbolicLink",
		[](vcpu&, emu_object<_UNICODE_STRING> symbolic_link_name) -> NTSTATUS
		{
			THREAD_LOG_INFO("IoDeleteSymbolicLink('{}')",
				narrow_wstring(win::read_unicode_string(symbolic_link_name)));

			return STATUS_SUCCESS;
		});

	// A create really opens a file out of win_filesystem, so a section mapped
	// over the handle it returns reads the bytes that are there. The disposition
	// says what to do about the file existing or not; the rest of the arguments
	// describe sharing and caching, which nothing here enforces.
	state.redirect(mod, "IoCreateFileEx",
		[st](vcpu& cpu, emu_object<std::uint64_t> file_handle, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			emu_object<_IO_STATUS_BLOCK> io_status_block, const addr_t allocation_size,
			const std::uint32_t file_attributes, const std::uint32_t share_access,
			const std::uint32_t disposition, const std::uint32_t create_options,
			const addr_t ea_buffer, const std::uint32_t ea_length,
			const std::uint32_t create_file_type, const addr_t extra_create_parameters,
			const std::uint32_t options, const addr_t driver_context) -> NTSTATUS
		{
			auto& space = *cpu.curr_addr_space();

			const emu_object<_UNICODE_STRING> name_obj(space, object_attributes
				? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
				: 0);

			const auto path = win_filesystem::normalize(
				narrow_wstring(win::read_unicode_string(name_obj)));

			THREAD_LOG_INFO("IoCreateFileEx('{}', access=0x{:X}, attributes=0x{:X}, share=0x{:X}, "
				"disposition={}, create_options=0x{:X}, ea=0x{:X}/{}, type={}, extra=0x{:X}, "
				"options=0x{:X}, context=0x{:X}, allocation_size=0x{:X})",
				path, desired_access, file_attributes, share_access, disposition, create_options,
				ea_buffer, ea_length, create_file_type, extra_create_parameters, options,
				driver_context, allocation_size);

			if (file_handle)
				file_handle.write(0);

			const auto result = open_file(*st, path, disposition, create_options, file_handle);

			write_status_block(io_status_block, result);

			return result.status;
		});

	// What a file object is called in the DOS namespace. Nothing here gives a
	// device a DOS name, so the answer is the path the file was opened by --
	// which is the name a caller logging it or comparing it actually wants.
	state.redirect(mod, "IoQueryFileDosDeviceName",
		[st](vcpu& cpu, const addr_t file_object,
			emu_object<addr_t> object_name_information) -> NTSTATUS
		{
			if (!object_name_information)
				return STATUS_INVALID_PARAMETER;

			const auto host = st->objs.get_object<file_host>(file_object);

			if (!host)
			{
				object_name_information.write(0);

				THREAD_LOG_WARN("IoQueryFileDosDeviceName: 0x{:X} is not a file object",
					file_object);

				return STATUS_OBJECT_NAME_NOT_FOUND;
			}

			// OBJECT_NAME_INFORMATION is a UNICODE_STRING with the characters
			// behind it, allocated for the caller to free with ExFreePool.
			auto& space = *cpu.curr_addr_space();
			const auto wide = widen_string(host->path);
			const auto bytes = static_cast<std::uint16_t>(wide.size() * sizeof(char16_t));
			const auto size = sizeof(_UNICODE_STRING) + bytes + sizeof(char16_t);

			const auto addr = st->pool.allocate(size, pool_tag("IoNm"), true);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			const auto buffer = addr + sizeof(_UNICODE_STRING);

			_UNICODE_STRING name{};
			name.Length = bytes;
			name.MaximumLength = static_cast<std::uint16_t>(bytes + sizeof(char16_t));
			name.Buffer = guest_ptr<char16_t>(buffer);

			emu_object<_UNICODE_STRING>(space, addr).write(name);
			space.write_mem(buffer, wide.data(), bytes);

			object_name_information.write(addr);

			THREAD_LOG_INFO("IoQueryFileDosDeviceName(0x{:X}) -> '{}' at 0x{:X}",
				file_object, host->path, addr);

			return STATUS_SUCCESS;
		});

	// Reached from a file object rather than a handle, and answered out of the
	// same file. Only the classes a driver asks about a file it just opened are
	// answered; the rest say so rather than leaving the buffer untouched.
	state.redirect(mod, "IoQueryFileInformation",
		[st](vcpu& cpu, const addr_t file_object, const std::uint32_t file_information_class,
			const std::uint32_t length, const addr_t file_information,
			emu_object<std::uint32_t> returned_length) -> NTSTATUS
		{
			if (returned_length)
				returned_length.write(0);

			const auto host = st->objs.get_object<file_host>(file_object);

			if (!host)
			{
				THREAD_LOG_WARN("IoQueryFileInformation: 0x{:X} is not a file object", file_object);
				return STATUS_INVALID_PARAMETER;
			}

			const auto result = write_file_information(*cpu.curr_addr_space(), *host,
				file_information_class, file_information, length);

			if (returned_length)
				returned_length.write(static_cast<std::uint32_t>(result.information));

			THREAD_LOG_INFO("IoQueryFileInformation(0x{:X}, '{}', class={}) -> 0x{:X}",
				file_object, host->path, file_information_class, result.status);

			return result.status;
		});

	// NtCreateFile and NtOpenFile are the same create underneath; open is the
	// one that will not make a file that is not there.
	auto create_file = [st](vcpu& cpu, emu_object<std::uint64_t> file_handle,
		const std::uint32_t desired_access, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
		emu_object<_IO_STATUS_BLOCK> io_status_block,
		[[maybe_unused]] emu_object<std::int64_t> allocation_size,
		const std::uint32_t file_attributes, const std::uint32_t share_access,
		const std::uint32_t create_disposition, const std::uint32_t create_options,
		const addr_t ea_buffer, const std::uint32_t ea_length) -> NTSTATUS
	{
		const auto path = object_path(cpu, object_attributes);

		if (file_handle)
			file_handle.write(0);

		const auto result = open_file(*st, path, create_disposition, create_options, file_handle);

		write_status_block(io_status_block, result);

		THREAD_LOG_INFO("NtCreateFile('{}', access=0x{:X}, attributes=0x{:X}, share=0x{:X}, "
			"disposition={}, options=0x{:X}, ea=0x{:X}/{}) -> 0x{:X}",
			path, desired_access, file_attributes, share_access, create_disposition,
			create_options, ea_buffer, ea_length, result.status);

		return result.status;
	};

	state.redirect_ntzw(mod, "OpenFile",
		[st](vcpu& cpu, emu_object<std::uint64_t> file_handle, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			emu_object<_IO_STATUS_BLOCK> io_status_block, const std::uint32_t share_access,
			const std::uint32_t open_options) -> NTSTATUS
		{
			const auto path = object_path(cpu, object_attributes);

			if (file_handle)
				file_handle.write(0);

			const auto result = open_file(*st, path, file_open, open_options, file_handle);

			write_status_block(io_status_block, result);

			THREAD_LOG_INFO("NtOpenFile('{}', access=0x{:X}, share=0x{:X}, options=0x{:X}) -> 0x{:X}",
				path, desired_access, share_access, open_options, result.status);

			return result.status;
		});

	// The file position carries between calls, which is what a caller that
	// passes no ByteOffset relies on. A negative offset is one of the two
	// documented sentinels for "use the current position".
	auto read_file = [st](vcpu& cpu, const std::uint64_t file_handle,
		[[maybe_unused]] const std::uint64_t event,
		[[maybe_unused]] const addr_t apc_routine, [[maybe_unused]] const addr_t apc_context,
		emu_object<_IO_STATUS_BLOCK> io_status_block, const addr_t buffer,
		const std::uint32_t length, emu_object<std::int64_t> byte_offset,
		[[maybe_unused]] emu_object<std::uint32_t> key) -> NTSTATUS
	{
		const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

		if (!host || !host->file)
		{
			THREAD_LOG_WARN("NtReadFile: handle 0x{:X} is not an open file", file_handle);
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		if (!buffer || !length)
		{
			write_status_block(io_status_block, {STATUS_INVALID_PARAMETER, 0});
			return STATUS_INVALID_PARAMETER;
		}

		const auto data = host->file->data();
		const auto offset = file_offset(byte_offset, host->position);

		if (offset >= data.size())
		{
			THREAD_LOG_INFO("NtReadFile('{}'): offset {} is at or past the end ({} bytes)",
				host->path, offset, data.size());

			write_status_block(io_status_block, {STATUS_END_OF_FILE, 0});
			return STATUS_END_OF_FILE;
		}

		const auto copied = std::min<std::uint64_t>(length, data.size() - offset);
		cpu.curr_addr_space()->write_mem(buffer, data.data() + offset, copied);

		host->position = offset + copied;

		write_status_block(io_status_block, {STATUS_SUCCESS, copied});

		THREAD_LOG_INFO("NtReadFile('{}', offset={}, {} bytes asked) -> {} bytes",
			host->path, offset, length, copied);

		return STATUS_SUCCESS;
	};

	auto write_file = [st](vcpu& cpu, const std::uint64_t file_handle,
		[[maybe_unused]] const std::uint64_t event,
		[[maybe_unused]] const addr_t apc_routine, [[maybe_unused]] const addr_t apc_context,
		emu_object<_IO_STATUS_BLOCK> io_status_block, const addr_t buffer,
		const std::uint32_t length, emu_object<std::int64_t> byte_offset,
		[[maybe_unused]] emu_object<std::uint32_t> key) -> NTSTATUS
	{
		const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

		if (!host || (!host->file && !host->console))
		{
			THREAD_LOG_WARN("NtWriteFile: handle 0x{:X} is not an open file", file_handle);
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		if (!buffer || !length)
		{
			write_status_block(io_status_block, {STATUS_INVALID_PARAMETER, 0});
			return STATUS_INVALID_PARAMETER;
		}

		std::vector<std::uint8_t> bytes(length);
		cpu.curr_addr_space()->read_mem(buffer, bytes.data(), length);

		// Straight out of the emulator, unbuffered: what the guest prints and
		// what the emulator logs are then in the order they happened.
		if (host->console)
		{
			std::fwrite(bytes.data(), 1, bytes.size(), stdout);
			std::fflush(stdout);

			write_status_block(io_status_block, {STATUS_SUCCESS, length});

			return STATUS_SUCCESS;
		}

		const auto offset = file_offset(byte_offset, host->position);

		// win_file::write replaces the file, so a write at an offset grows a
		// copy of what is there, drops the new bytes in, and puts it back.
		const auto current = host->file->data();

		if (offset + length > current.size())
		{
			std::vector<std::uint8_t> grown(current.begin(), current.end());
			grown.resize(offset + length, 0);
			std::memcpy(grown.data() + offset, bytes.data(), length);
			host->file->write(grown.data(), grown.size());
		}
		else
		{
			std::memcpy(host->file->data().data() + offset, bytes.data(), length);
		}

		host->position = offset + length;

		write_status_block(io_status_block, {STATUS_SUCCESS, length});

		THREAD_LOG_INFO("NtWriteFile('{}', offset={}, {} bytes)", host->path, offset, length);

		return STATUS_SUCCESS;
	};

	auto query_information_file = [st](vcpu& cpu, const std::uint64_t file_handle,
		emu_object<_IO_STATUS_BLOCK> io_status_block, const addr_t file_information,
		const std::uint32_t length, const std::uint32_t file_information_class) -> NTSTATUS
	{
		const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

		if (!host || !host->file)
		{
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		auto& space = *cpu.curr_addr_space();
		const auto status = write_file_information(space, *host, file_information_class,
			file_information, length);

		write_status_block(io_status_block, status);

		THREAD_LOG_INFO("NtQueryInformationFile('{}', class={}) -> 0x{:X}",
			host->path, file_information_class, status.status);

		return status.status;
	};

	// Nothing sits behind the store to push a write out to.
	auto flush_buffers_file = [st](vcpu&, const std::uint64_t file_handle,
		emu_object<_IO_STATUS_BLOCK> io_status_block) -> NTSTATUS
	{
		const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

		if (!host)
		{
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		write_status_block(io_status_block, {STATUS_SUCCESS, 0});

		THREAD_LOG_INFO("NtFlushBuffersFile('{}'): the store is memory, so there is nothing to "
			"flush", host->path);

		return STATUS_SUCCESS;
	};

	// One entry per call, which is what ReturnSingleEntry asks for and what a
	// caller looping until STATUS_NO_MORE_FILES handles either way. The scan
	// position rides on the file object, so RestartScan is what rewinds it.
	auto query_directory_file = [st](vcpu& cpu, const std::uint64_t file_handle,
		[[maybe_unused]] const std::uint64_t event,
		[[maybe_unused]] const addr_t apc_routine, [[maybe_unused]] const addr_t apc_context,
		emu_object<_IO_STATUS_BLOCK> io_status_block, const addr_t file_information,
		const std::uint32_t length, const std::uint32_t file_information_class,
		const bool return_single_entry, emu_object<_UNICODE_STRING> file_name,
		const bool restart_scan) -> NTSTATUS
	{
		const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

		if (!host)
		{
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		if (file_information_class != file_directory_information
			&& file_information_class != file_both_directory_information
			&& file_information_class != file_full_directory_information)
		{
			THREAD_LOG_WARN("NtQueryDirectoryFile: unhandled class {}", file_information_class);
			write_status_block(io_status_block, {STATUS_INVALID_INFO_CLASS, 0});
			return STATUS_INVALID_INFO_CLASS;
		}

		if (restart_scan)
			host->position = 0;

		const auto entries = st->fs.list_dir(host->path);

		if (host->position >= entries.size())
		{
			THREAD_LOG_INFO("NtQueryDirectoryFile('{}'): {} entries, so that is the end",
				host->path, entries.size());

			write_status_block(io_status_block, {STATUS_NO_MORE_FILES, 0});
			return STATUS_NO_MORE_FILES;
		}

		const auto& entry = entries[static_cast<std::size_t>(host->position)];
		const auto wide = widen_string(entry.name);
		const auto name_bytes = static_cast<std::uint32_t>(wide.size() * sizeof(char16_t));
		const auto needed = sizeof(file_directory_information_t) + name_bytes;

		if (length < needed)
		{
			write_status_block(io_status_block, {STATUS_BUFFER_TOO_SMALL, 0});
			return STATUS_BUFFER_TOO_SMALL;
		}

		file_directory_information_t info{};
		info.next_entry_offset = 0;
		info.end_of_file = static_cast<std::int64_t>(entry.size);
		info.allocation_size = info.end_of_file;
		info.file_attributes = entry.is_directory ? file_attribute_directory : file_attribute_normal;
		info.file_name_length = name_bytes;

		auto& space = *cpu.curr_addr_space();
		emu_object<file_directory_information_t>(space, file_information).write(info);
		space.write_mem(file_information + sizeof(info), wide.data(), name_bytes);

		++host->position;

		write_status_block(io_status_block, {STATUS_SUCCESS, needed});

		THREAD_LOG_INFO("NtQueryDirectoryFile('{}', single={}, filter='{}') -> '{}'",
			host->path, return_single_entry,
			narrow_wstring(win::read_unicode_string(file_name)), entry.name);

		return STATUS_SUCCESS;
	};

	// Answered without opening the file, which is the point of them.
	auto query_attributes_file = [st](vcpu& cpu,
		emu_object<_OBJECT_ATTRIBUTES> object_attributes, const addr_t file_information,
		const bool full) -> NTSTATUS
	{
		const auto path = object_path(cpu, object_attributes);
		const auto file = st->fs.open(path);
		const bool directory = !file && st->fs.dir_exists(path);

		if (!file && !directory)
		{
			THREAD_LOG_WARN("NtQueryAttributesFile: '{}' is not there", path);
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}

		const auto size = static_cast<std::int64_t>(file ? file->size() : 0);
		const auto attributes = directory ? file_attribute_directory : file_attribute_normal;

		auto& space = *cpu.curr_addr_space();

		if (full)
		{
			file_network_open_information_t info{};
			info.allocation_size = size;
			info.end_of_file = size;
			info.file_attributes = attributes;

			emu_object<file_network_open_information_t>(space, file_information).write(info);
		}
		else
		{
			file_basic_information_t info{};
			info.file_attributes = attributes;

			emu_object<file_basic_information_t>(space, file_information).write(info);
		}

		THREAD_LOG_INFO("NtQuery{}AttributesFile('{}') -> {} bytes, attributes=0x{:X}",
			full ? "Full" : "", path, size, attributes);

		return STATUS_SUCCESS;
	};

	// One volume, and a caller asking about it wants to know it is a fixed disk
	// with room on it rather than anything specific.
	auto query_volume_information_file = [st](vcpu& cpu, const std::uint64_t file_handle,
		emu_object<_IO_STATUS_BLOCK> io_status_block, const addr_t fs_information,
		const std::uint32_t length, const std::uint32_t fs_information_class) -> NTSTATUS
	{
		const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

		if (!host)
		{
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		auto& space = *cpu.curr_addr_space();

		if (fs_information_class == file_fs_device_information)
		{
			if (length < sizeof(file_fs_device_information_t))
			{
				write_status_block(io_status_block, {STATUS_INFO_LENGTH_MISMATCH, 0});
				return STATUS_INFO_LENGTH_MISMATCH;
			}

			const file_fs_device_information_t info{
				host->console ? file_device_console : file_device_disk, 0};
			emu_object<file_fs_device_information_t>(space, fs_information).write(info);

			write_status_block(io_status_block, {STATUS_SUCCESS, sizeof(info)});

			THREAD_LOG_INFO("NtQueryVolumeInformationFile('{}', FileFsDeviceInformation)",
				host->path);

			return STATUS_SUCCESS;
		}

		THREAD_LOG_WARN("NtQueryVolumeInformationFile: unhandled class {}", fs_information_class);

		write_status_block(io_status_block, {STATUS_INVALID_INFO_CLASS, 0});

		return STATUS_INVALID_INFO_CLASS;
	};

	state.redirect_ntzw(mod, "CreateFile", create_file);
	state.redirect_ntzw(mod, "ReadFile", read_file);
	state.redirect_ntzw(mod, "WriteFile", write_file);
	state.redirect_ntzw(mod, "QueryInformationFile", query_information_file);
	state.redirect_ntzw(mod, "FlushBuffersFile", flush_buffers_file);
	state.redirect_ntzw(mod, "QueryDirectoryFile", query_directory_file);
	state.redirect_ntzw(mod, "QueryVolumeInformationFile", query_volume_information_file);

	state.redirect_ntzw(mod, "QueryAttributesFile",
		[query_attributes_file](vcpu& cpu, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			const addr_t file_information) -> NTSTATUS
		{
			return query_attributes_file(cpu, object_attributes, file_information, false);
		});

	state.redirect_ntzw(mod, "QueryFullAttributesFile",
		[query_attributes_file](vcpu& cpu, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			const addr_t file_information) -> NTSTATUS
		{
			return query_attributes_file(cpu, object_attributes, file_information, true);
		});

	// Nothing builds an irp, so there is no dispatch routine to send the code to
	// and no driver to write the output buffer. The call is reported as having
	// worked with nothing returned, which is what a control code the target
	// ignores looks like.
	auto control_file = [st](vcpu& cpu, const std::uint64_t file_handle, const addr_t event,
		const addr_t apc_routine, const addr_t apc_context,
		emu_object<_IO_STATUS_BLOCK> io_status_block, const std::uint32_t control_code,
		const addr_t input_buffer, const std::uint32_t input_length,
		const addr_t output_buffer, const std::uint32_t output_length,
		const std::string_view who) -> NTSTATUS
	{
		const auto host = st->sys_proc->handle_table().get_object<file_host>(file_handle);

		if (!host)
		{
			THREAD_LOG_WARN("{}: handle 0x{:X} is not open", who, file_handle);
			write_status_block(io_status_block, {STATUS_INVALID_HANDLE, 0});
			return STATUS_INVALID_HANDLE;
		}

		THREAD_LOG_WARN("{}('{}', code=0x{:X}, in=0x{:X}/{}, out=0x{:X}/{}, event=0x{:X}, "
			"apc=0x{:X}/0x{:X}): nothing here builds an irp, so nothing wrote the output "
			"buffer",
			who, host->path, control_code, input_buffer, input_length,
			output_buffer, output_length, event, apc_routine, apc_context);

		write_status_block(io_status_block, {STATUS_SUCCESS, 0});

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "DeviceIoControlFile",
		[control_file](vcpu& cpu, const std::uint64_t file_handle, const addr_t event,
			const addr_t apc_routine, const addr_t apc_context,
			emu_object<_IO_STATUS_BLOCK> io_status_block, const std::uint32_t control_code,
			const addr_t input_buffer, const std::uint32_t input_length,
			const addr_t output_buffer, const std::uint32_t output_length) -> NTSTATUS
		{
			return control_file(cpu, file_handle, event, apc_routine, apc_context,
				std::move(io_status_block), control_code, input_buffer, input_length,
				output_buffer, output_length, "NtDeviceIoControlFile");
		});

	state.redirect_ntzw(mod, "FsControlFile",
		[control_file](vcpu& cpu, const std::uint64_t file_handle, const addr_t event,
			const addr_t apc_routine, const addr_t apc_context,
			emu_object<_IO_STATUS_BLOCK> io_status_block, const std::uint32_t control_code,
			const addr_t input_buffer, const std::uint32_t input_length,
			const addr_t output_buffer, const std::uint32_t output_length) -> NTSTATUS
		{
			return control_file(cpu, file_handle, event, apc_routine, apc_context,
				std::move(io_status_block), control_code, input_buffer, input_length,
				output_buffer, output_length, "NtFsControlFile");
		});
}
