#include "fltmgr.hpp"
#include "../win_kernel.hpp"
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

// The filter a driver registers, and the ports it opens on it. Nothing here
// sends an operation through a filter, so what these objects carry is what the
// driver put in them and can read back.
struct filter_host final : win_object
{
	addr_t driver_object = 0;
	bool filtering = false;
};

struct port_host final : win_object
{
	addr_t filter = 0;
	addr_t connect_notify = 0;
	addr_t disconnect_notify = 0;
	addr_t message_notify = 0;
};

// FLT_FILE_NAME_INFORMATION, a WDK structure ending in the buffer its counted
// strings point into. The same on both architectures.
#pragma pack(push, 8)
struct flt_file_name_information_t
{
	std::uint16_t  size;
	std::uint16_t  name_length;
	std::uint32_t  format;
	addr_t         next_extension;
	_UNICODE_STRING name;
	_UNICODE_STRING volume;
	_UNICODE_STRING share;
	_UNICODE_STRING extension;
	_UNICODE_STRING stream;
	_UNICODE_STRING final_component;
	_UNICODE_STRING parent_dir;
};
#pragma pack(pop)

// A filter object body is opaque to the driver: it holds the pointer and hands
// it back. Sized so a driver poking about inside one stays in its own memory.
constexpr std::size_t filter_body_size = 0x100;
constexpr std::size_t port_body_size = 0x100;
constexpr std::size_t security_descriptor_size = 0x40;

addr_t create_opaque(win_kernel_state& state, const std::size_t size,
	std::shared_ptr<win_object> host)
{
	const std::vector<std::uint8_t> body(size, 0);

	return state.objs.create_object(0, body.data(), body.size(), std::move(host),
		prot_rw | prot_supervisor);
}

}

// The filter manager. A minifilter registers, opens its communication port and
// starts filtering; nothing here sends it an operation to filter, so what these
// do is give it the objects it needs to get that far and report what it asked
// for -- which is how far a minifilter gets before it waits for io that never
// comes.
void modules::register_fltmgr(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// A push lock with no contention is bookkeeping: one thread at a time
	// reaches a handler, and nothing here blocks.
	auto push_lock = [](vcpu&, const addr_t push_lock_address)
	{
		THREAD_LOG_INFO("FltPushLock(0x{:X})", push_lock_address);
	};

	state.redirect(mod, "FltAcquirePushLockExclusive", push_lock);
	state.redirect(mod, "FltAcquirePushLockShared", push_lock);
	state.redirect(mod, "FltReleasePushLock", push_lock);

	// The registration structure names the callbacks the filter wants. They are
	// read out and reported, because a filter registering for operations that
	// will never arrive is the thing worth knowing from a run.
	state.redirect(mod, "FltRegisterFilter",
		[st](vcpu& cpu, const addr_t driver_object, emu_object<void> registration,
			emu_object<addr_t> ret_filter) -> NTSTATUS
		{
			if (!ret_filter || !registration)
				return STATUS_INVALID_PARAMETER;

			// FLT_REGISTRATION begins with Size and Version, then Flags, then a
			// context registration pointer and the operation registration
			// pointer. Only the counts are read; the callback table behind them
			// is the filter's own shape.
			auto& space = *cpu.curr_addr_space();
			const auto size = space.read_mem<std::uint16_t>(registration.address());
			const auto version = space.read_mem<std::uint16_t>(registration.address() + 2);

			auto host = std::make_shared<filter_host>();
			host->driver_object = driver_object;

			const auto addr = create_opaque(*st, filter_body_size, std::move(host));

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			ret_filter.write(addr);

			THREAD_LOG_INFO("FltRegisterFilter(driver=0x{:X}, registration=0x{:X}, size={}, "
				"version={}) -> filter=0x{:X}",
				driver_object, registration.address(), size, version, addr);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "FltStartFiltering", [st](vcpu&, const addr_t filter) -> NTSTATUS
	{
		const auto host = st->objs.get_object<filter_host>(filter);

		if (!host)
		{
			THREAD_LOG_WARN("FltStartFiltering: 0x{:X} is not a filter", filter);
			return STATUS_INVALID_PARAMETER;
		}

		host->filtering = true;

		THREAD_LOG_WARN("FltStartFiltering(0x{:X}): the filter is attached, and nothing here "
			"sends it an operation to filter", filter);

		return STATUS_SUCCESS;
	});

	state.redirect(mod, "FltUnregisterFilter", [st](vcpu&, const addr_t filter)
	{
		const auto host = st->objs.get_object<filter_host>(filter);

		if (host)
			host->filtering = false;

		THREAD_LOG_INFO("FltUnregisterFilter(0x{:X})", filter);

		st->objs.dereference_object(filter);
	});

	// A descriptor the caller frees with FltFreeSecurityDescriptor, so it comes
	// out of the pool. Nothing checks a descriptor, so what is in it is only
	// what makes it a distinct allocation.
	state.redirect(mod, "FltBuildDefaultSecurityDescriptor",
		[st](vcpu&, emu_object<addr_t> security_descriptor,
			const std::uint32_t desired_access) -> NTSTATUS
		{
			if (!security_descriptor)
				return STATUS_INVALID_PARAMETER;

			const auto addr = st->pool.allocate(security_descriptor_size,
				pool_tag("FltS"), true);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			security_descriptor.write(addr);

			THREAD_LOG_INFO("FltBuildDefaultSecurityDescriptor(access=0x{:X}) -> 0x{:X}",
				desired_access, addr);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "FltFreeSecurityDescriptor",
		[st](vcpu&, const addr_t security_descriptor)
		{
			const auto freed = st->pool.free(security_descriptor);

			if (!freed)
			{
				THREAD_LOG_ERR("FltFreeSecurityDescriptor: 0x{:X} was not allocated here",
					security_descriptor);
				return;
			}

			THREAD_LOG_INFO("FltFreeSecurityDescriptor(0x{:X})", security_descriptor);
		});

	// The port a filter opens for user mode to connect to. Nothing here is user
	// mode, so the connect and message callbacks are recorded and never called.
	state.redirect(mod, "FltCreateCommunicationPort",
		[st](vcpu& cpu, const addr_t filter, emu_object<addr_t> server_port,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes, const addr_t server_port_cookie,
			const addr_t connect_notify_callback, const addr_t disconnect_notify_callback,
			const addr_t message_notify_callback,
			const std::int32_t max_connections) -> NTSTATUS
		{
			if (!server_port)
				return STATUS_INVALID_PARAMETER;

			auto& space = *cpu.curr_addr_space();

			const emu_object<_UNICODE_STRING> name_obj(space, object_attributes
				? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
				: 0);

			auto host = std::make_shared<port_host>();
			host->filter = filter;
			host->connect_notify = connect_notify_callback;
			host->disconnect_notify = disconnect_notify_callback;
			host->message_notify = message_notify_callback;

			const auto addr = create_opaque(*st, port_body_size, std::move(host));

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			server_port.write(addr);

			THREAD_LOG_WARN("FltCreateCommunicationPort(filter=0x{:X}, '{}', cookie=0x{:X}, "
				"connect=0x{:X}, disconnect=0x{:X}, message=0x{:X}, max={}) -> 0x{:X}: "
				"nothing here connects to a port",
				filter, narrow_wstring(win::read_unicode_string(name_obj)), server_port_cookie,
				connect_notify_callback, disconnect_notify_callback, message_notify_callback,
				max_connections, addr);

			return STATUS_SUCCESS;
		});

	auto close_port = [st](vcpu&, const addr_t port)
	{
		THREAD_LOG_INFO("FltCloseCommunicationPort(0x{:X})", port);
		st->objs.dereference_object(port);
	};

	state.redirect(mod, "FltCloseCommunicationPort", close_port);
	state.redirect(mod, "FltCloseClientPort",
		[](vcpu&, const addr_t filter, emu_object<addr_t> client_port)
		{
			THREAD_LOG_INFO("FltCloseClientPort(filter=0x{:X}, port=0x{:X})",
				filter, client_port.address());

			if (client_port)
				client_port.write(0);
		});

	// The name of the file an operation is about. The file object behind it is
	// one the io manager here made, so the name is the path it was opened by.
	state.redirect(mod, "FltGetFileNameInformationUnsafe",
		[st](vcpu& cpu, const addr_t file_object, const addr_t instance,
			const std::uint32_t name_options, emu_object<addr_t> file_name_information) -> NTSTATUS
		{
			if (!file_name_information)
				return STATUS_INVALID_PARAMETER;

			const auto host = st->objs.get_object<file_host>(file_object);

			if (!host)
			{
				THREAD_LOG_WARN("FltGetFileNameInformationUnsafe: 0x{:X} is not a file object",
					file_object);
				return STATUS_INVALID_PARAMETER;
			}

			const auto wide = widen_string(host->path);
			const auto bytes = static_cast<std::uint16_t>(wide.size() * sizeof(wchar_t));
			const auto size = sizeof(flt_file_name_information_t) + bytes;

			const auto addr = st->pool.allocate(size, pool_tag("FltN"), true);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			const auto buffer = addr + sizeof(flt_file_name_information_t);

			// Name covers the whole path; the components are what
			// FltParseFileNameInformation fills in afterwards.
			flt_file_name_information_t info{};
			info.size = static_cast<std::uint16_t>(size);
			info.name_length = bytes;
			info.format = name_options;
			info.name.Length = bytes;
			info.name.MaximumLength = bytes;
			info.name.Buffer = guest_ptr<wchar_t>(buffer);

			auto& space = *cpu.curr_addr_space();
			emu_object<flt_file_name_information_t>(space, addr).write(info);
			space.write_mem(buffer, wide.data(), bytes);

			file_name_information.write(addr);

			THREAD_LOG_INFO("FltGetFileNameInformationUnsafe(0x{:X}, instance=0x{:X}, "
				"options=0x{:X}) -> '{}' at 0x{:X}",
				file_object, instance, name_options, host->path, addr);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "FltReleaseFileNameInformation",
		[st](vcpu&, const addr_t file_name_information)
		{
			const auto freed = st->pool.free(file_name_information);

			if (!freed)
			{
				THREAD_LOG_ERR("FltReleaseFileNameInformation: 0x{:X} was not allocated here",
					file_name_information);
				return;
			}

			THREAD_LOG_INFO("FltReleaseFileNameInformation(0x{:X})", file_name_information);
		});

	// Splits the whole path the structure already carries into the components a
	// filter matches on: the last path separator divides the parent directory
	// from the final component, and the last dot in that gives the extension.
	state.redirect(mod, "FltParseFileNameInformation",
		[](vcpu& cpu, emu_object<flt_file_name_information_t> file_name_information) -> NTSTATUS
		{
			if (!file_name_information)
				return STATUS_INVALID_PARAMETER;

			auto info = file_name_information.read();
			auto& space = *cpu.curr_addr_space();

			const auto buffer = guest_va(info.name.Buffer);
			const auto chars = info.name.Length / sizeof(wchar_t);

			if (!buffer || !chars)
				return STATUS_INVALID_PARAMETER;

			std::wstring path(chars, L'\0');
			space.read_mem(buffer, path.data(), info.name.Length);

			const auto slash = path.find_last_of(L"\\/");
			const auto component_at = slash == std::wstring::npos ? 0 : slash + 1;

			const auto counted = [&](const std::size_t at, const std::size_t count)
			{
				const auto bytes = static_cast<std::uint16_t>(count * sizeof(wchar_t));

				return _UNICODE_STRING{
					.Length = bytes,
					.MaximumLength = bytes,
					.Buffer = guest_ptr<wchar_t>(buffer + at * sizeof(wchar_t)),
				};
			};

			info.parent_dir = counted(0, component_at);
			info.final_component = counted(component_at, chars - component_at);

			const auto dot = path.find_last_of(L'.');

			if (dot != std::wstring::npos && dot > component_at)
				info.extension = counted(dot + 1, chars - dot - 1);

			file_name_information.write(info);

			THREAD_LOG_INFO("FltParseFileNameInformation('{}'): component '{}'",
				narrow_wstring(path), narrow_wstring(path.substr(component_at)));

			return STATUS_SUCCESS;
		});
}
