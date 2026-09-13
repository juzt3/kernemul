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
#include <string_view>

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

// FILE_INFORMATION_CLASS, the two answerable about a file that was just opened.
enum file_information_class : std::uint32_t
{
	file_standard_information = 5,
	file_position_information = 14,
};

#pragma pack(push, 4)
struct file_standard_information_t
{
	std::int64_t  allocation_size;
	std::int64_t  end_of_file;
	std::uint32_t number_of_links;
	std::uint8_t  delete_pending;
	std::uint8_t  directory;
	std::uint16_t padding;
};
#pragma pack(pop)

static_assert(sizeof(file_standard_information_t) == 0x18);

struct open_result
{
	NTSTATUS status = STATUS_SUCCESS;
	std::uint64_t information = 0;
};

// What every create path comes down to: find or make the file, and say which of
// the two happened. The disposition is the whole of the decision.
open_result open_file(win_kernel_state& state, const std::string& path,
	const std::uint32_t disposition, emu_object<std::uint64_t> file_handle)
{
	if (path.empty())
		return { STATUS_OBJECT_NAME_INVALID, 0 };

	const bool existed = state.fs.exists(path);

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
	status.Status = static_cast<long>(result.status);
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

			const auto result = open_file(*st, path, disposition, file_handle);

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
			const auto bytes = static_cast<std::uint16_t>(wide.size() * sizeof(wchar_t));
			const auto size = sizeof(_UNICODE_STRING) + bytes + sizeof(wchar_t);

			const auto addr = st->pool.allocate(size, pool_tag("IoNm"), true);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			const auto buffer = addr + sizeof(_UNICODE_STRING);

			_UNICODE_STRING name{};
			name.Length = bytes;
			name.MaximumLength = static_cast<std::uint16_t>(bytes + sizeof(wchar_t));
			name.Buffer = guest_ptr<wchar_t>(buffer);

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

			auto& space = *cpu.curr_addr_space();
			const auto size = static_cast<std::int64_t>(host->file->size());

			if (file_information_class == file_standard_information)
			{
				if (length < sizeof(file_standard_information_t))
					return STATUS_INFO_LENGTH_MISMATCH;

				file_standard_information_t info{};
				info.allocation_size = size;
				info.end_of_file = size;
				info.number_of_links = 1;

				emu_object<file_standard_information_t>(space, file_information).write(info);

				if (returned_length)
					returned_length.write(sizeof(info));

				THREAD_LOG_INFO("IoQueryFileInformation(0x{:X}, FileStandardInformation): "
					"'{}' is {} bytes", file_object, host->path, size);

				return STATUS_SUCCESS;
			}

			if (file_information_class == file_position_information)
			{
				if (length < sizeof(std::int64_t))
					return STATUS_INFO_LENGTH_MISMATCH;

				emu_object<std::int64_t>(space, file_information)
					.write(static_cast<std::int64_t>(host->position));

				if (returned_length)
					returned_length.write(sizeof(std::int64_t));

				THREAD_LOG_INFO("IoQueryFileInformation(0x{:X}, FilePositionInformation) -> {}",
					file_object, host->position);

				return STATUS_SUCCESS;
			}

			THREAD_LOG_WARN("IoQueryFileInformation(0x{:X}, class={}): unhandled class",
				file_object, file_information_class);

			return STATUS_INVALID_INFO_CLASS;
		});
}
