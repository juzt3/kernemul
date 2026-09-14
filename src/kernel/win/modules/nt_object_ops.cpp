#include "nt_object_ops.hpp"
#include "../win_kernel.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../process_params.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/string.hpp"
#include "../../../util/log.hpp"
#include <array>
#include <string>

namespace
{

// A directory and a symbolic link are both reached only by handle, so their
// bodies are opaque and what they hold lives here.
constexpr std::size_t namespace_object_body_size = 0x10;

struct directory_host final : win_object {};

struct symbolic_link_host final : win_object
{
	std::string target;
};

// OB_CALLBACK_REGISTRATION and OB_OPERATION_REGISTRATION are WDK types the
// kernel does not store, so they are not in the PDB. Both are the same on each
// architecture: every member is pointer sized or smaller and naturally aligned.
#pragma pack(push, 8)
struct ob_callback_registration_t
{
	std::uint16_t   version;
	std::uint16_t   operation_count;
	std::uint32_t   flags;
	_UNICODE_STRING altitude;
	addr_t          registration_context;
	addr_t          operation_registration;
};

struct ob_operation_registration_t
{
	addr_t        object_type;
	std::uint32_t operations;
	std::uint32_t padding;
	addr_t        pre_operation;
	addr_t        post_operation;
};
#pragma pack(pop)

}

void modules::register_ntoskrnl_object_ops(win_kernel_state& state, proc_module& mod)
{
	auto* sys_proc = state.sys_proc.get();

	state.redirect(mod, "ObReferenceObjectByHandle",
		[sys_proc, &objs = state.objs](vcpu& cpu,
			std::uint64_t handle, [[maybe_unused]] std::uint32_t desired_access,
			[[maybe_unused]] emu_object<void> object_type, [[maybe_unused]] std::uint8_t access_mode,
			emu_object<std::uint64_t> object_out) -> NTSTATUS
		{
			THREAD_LOG_INFO("ObReferenceObjectByHandle(handle=0x{:X}, object_out=0x{:X})",
				handle, object_out.address());

			const auto entry = sys_proc->handle_table().lookup_handle(handle);
			if (!entry)
			{
				THREAD_LOG_WARN("ObReferenceObjectByHandle: invalid handle 0x{:X}", handle);
				return STATUS_INVALID_HANDLE;
			}

			objs.reference_object(entry->body_addr);

			if (object_out)
				object_out.write(entry->body_addr);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "ObfReferenceObject",
		[&objs = state.objs](vcpu&, addr_t object) -> void
		{
			THREAD_LOG_INFO("ObfReferenceObject(object=0x{:X})", object);
			objs.reference_object(object);
		});

	auto deref = [&objs = state.objs](vcpu&, addr_t object) -> void
	{
		THREAD_LOG_INFO("ObfDereferenceObject(object=0x{:X})", object);
		objs.dereference_object(object);
	};

	state.redirect(mod, "ObfDereferenceObject", deref);
	state.redirect(mod, "ObfDereferenceObjectWithTag", deref);

	auto close_fn = [sys_proc](vcpu&, std::uint64_t handle) -> NTSTATUS
	{
		THREAD_LOG_INFO("NtClose(handle=0x{:X})", handle);

		if (!sys_proc->handle_table().close_handle(handle))
		{
			THREAD_LOG_WARN("NtClose: invalid handle 0x{:X}", handle);
			return STATUS_INVALID_HANDLE;
		}

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "Close", close_fn);

	// An object callback is told before and after a handle is opened or
	// duplicated. Nothing here opens a handle through the object manager path
	// that would notify one, so a driver filtering handle access sees none of
	// the traffic these handlers make -- which is the whole point of registering
	// one, so this is a warning rather than a note.
	state.redirect(mod, "ObRegisterCallbacks",
		[&objs = state.objs](vcpu& cpu, emu_object<void> callback_registration,
			emu_object<addr_t> registration_handle) -> NTSTATUS
		{
			if (!callback_registration || !registration_handle)
				return STATUS_INVALID_PARAMETER;

			auto& space = *cpu.curr_addr_space();
			const emu_object<ob_callback_registration_t> registration(space,
				callback_registration.address());

			const auto reg = registration.read();
			const auto altitude = narrow_wstring(win::read_unicode_string(
				emu_object<_UNICODE_STRING>(space, registration.address()
					+ offsetof(ob_callback_registration_t, altitude))));

			THREAD_LOG_INFO("ObRegisterCallbacks(version={}, altitude='{}', {} operation(s))",
				reg.version, altitude, reg.operation_count);

			// Which object types a filter wants, and what it would be called
			// with. Reported because it is the whole of what the registration
			// says, and none of it is ever acted on.
			for (std::uint16_t i = 0; i < reg.operation_count; ++i)
			{
				const emu_object<ob_operation_registration_t> op(space,
					reg.operation_registration + i * sizeof(ob_operation_registration_t));

				const auto entry = op.read();
				const auto type = space.read_mem<addr_t>(entry.object_type);

				THREAD_LOG_INFO("  operation[{}]: type=0x{:X} (at 0x{:X}), operations=0x{:X}, "
					"pre=0x{:X}, post=0x{:X}",
					i, type, entry.object_type, entry.operations,
					entry.pre_operation, entry.post_operation);
			}

			const auto count = reg.operation_count;

			const std::uint8_t body[sizeof(addr_t)] = {};
			const auto handle = objs.create_object(0, body, sizeof(body), {},
				prot_rw | prot_supervisor);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			registration_handle.write(handle);

			THREAD_LOG_WARN("ObRegisterCallbacks(0x{:X}, {} operation(s)) -> 0x{:X}: nothing here "
				"notifies an object callback", callback_registration.address(), count, handle);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "ObUnRegisterCallbacks", [](vcpu&, const addr_t registration_handle)
	{
		THREAD_LOG_INFO("ObUnRegisterCallbacks(0x{:X})", registration_handle);
	});

	// An object type is a global ntoskrnl points at -- PsThreadType,
	// IoFileObjectType and the rest -- so the answer is the value of whichever
	// of those globals matches the kind of object this is. Nothing here builds
	// a type index table, so the kind comes from the host object instead.
	state.redirect(mod, "ObGetObjectType",
		[st = &state, m = &mod](vcpu& cpu, const addr_t object) -> addr_t
		{
			std::string_view symbol;

			if (st->objs.get_object<file_host>(object))
				symbol = "IoFileObjectType";
			else if (st->objs.get_object<section_host>(object))
				symbol = "MmSectionObjectType";
			else if (st->objs.get_object<thread_object>(object))
				symbol = "PsThreadType";

			if (symbol.empty())
			{
				THREAD_LOG_WARN("ObGetObjectType(0x{:X}): nothing here knows what kind of object "
					"that is", object);
				return 0;
			}

			const auto global = m->find_symbol(symbol);

			if (!global)
			{
				THREAD_LOG_WARN("ObGetObjectType: {} is not in {}", symbol, m->name);
				return 0;
			}

			const auto type = cpu.curr_addr_space()->read_mem<addr_t>(*global);

			THREAD_LOG_INFO("ObGetObjectType(0x{:X}) -> 0x{:X} ({})", object, type, symbol);

			return type;
		});

	// A handle onto an object the caller already holds a pointer to. The object
	// manager here has no type to check the pointer against, so what it can
	// check is that the address really is one of its objects.
	state.redirect(mod, "ObOpenObjectByPointer",
		[st = &state](vcpu&, const addr_t object, const std::uint32_t handle_attributes,
			const addr_t passed_access_state, const std::uint32_t desired_access,
			const addr_t object_type, const std::uint8_t access_mode,
			emu_object<std::uint64_t> handle) -> NTSTATUS
		{
			if (!handle)
				return STATUS_INVALID_PARAMETER;

			// Not checked against the object manager: a driver reaches this with
			// a pointer it got from anywhere -- an EPROCESS, a file object the
			// io manager made -- and only some of those were created here.
			st->objs.reference_object(object);
			const auto value = st->sys_proc->handle_table().create_handle(object, desired_access);

			handle.write(value);

			THREAD_LOG_INFO("ObOpenObjectByPointer(0x{:X}, attributes=0x{:X}, access_state=0x{:X}, "
				"access=0x{:X}, type=0x{:X}, mode={}) -> handle=0x{:X}",
				object, handle_attributes, passed_access_state, desired_access, object_type,
				access_mode, value);

			return STATUS_SUCCESS;
		});

	// The handle table of a process, which every process here shares: there is
	// one table, hanging off the system process. The address is what
	// ObDereferenceProcessHandleTable is given back.
	state.redirect(mod, "ObReferenceProcessHandleTable",
		[](vcpu&, emu_object<_EPROCESS> process) -> addr_t
		{
			const auto table = process
				? guest_va(process.field(&_EPROCESS::ObjectTable).read()) : 0;

			THREAD_LOG_INFO("ObReferenceProcessHandleTable(0x{:X}) -> 0x{:X}",
				process.address(), table);

			return table;
		});

	// Walking a handle table means calling the caller back once per handle, and
	// nothing here calls back into the guest. Returning null says the walk
	// finished without a match, which is what a caller searching for one reads.
	state.redirect(mod, "ExEnumHandleTable",
		[](vcpu&, const addr_t handle_table, const addr_t callback, const addr_t context,
			emu_object<std::uint64_t> handle) -> bool
		{
			if (handle)
				handle.write(0);

			THREAD_LOG_WARN("ExEnumHandleTable(table=0x{:X}, callback=0x{:X}, context=0x{:X}): "
				"nothing here calls back into the guest, so no handle is enumerated",
				handle_table, callback, context);

			return false;
		});

	// Nothing builds the directories these names would hang off, so opening one
	// makes it: the handle is a real handle to a real object, and a caller that
	// enumerates it finds it empty rather than finding the open refused.
	auto attribute_name = [](vcpu& cpu, const emu_object<_OBJECT_ATTRIBUTES>& object_attributes)
	{
		auto& space = *cpu.curr_addr_space();

		const emu_object<_UNICODE_STRING> name(space, object_attributes
			? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
			: 0);

		return narrow_wstring(win::read_unicode_string(name));
	};

	auto open_namespace_object = [st = &state](std::shared_ptr<win_object> host,
		const std::string& name, const std::uint32_t desired_access) -> std::uint64_t
	{
		if (const auto existing = st->objs.lookup_named_object(name))
			return st->sys_proc->handle_table().create_handle(existing, desired_access);

		const std::array<std::uint8_t, namespace_object_body_size> body{};
		const auto addr = st->objs.create_object(0, body.data(), body.size(), std::move(host),
			prot_rw | prot_supervisor);

		if (!addr)
			return 0;

		st->objs.register_named_object(name, addr);

		return st->sys_proc->handle_table().create_handle(addr, desired_access);
	};

	state.redirect_ntzw(mod, "OpenDirectoryObject",
		[attribute_name, open_namespace_object](vcpu& cpu,
			emu_object<std::uint64_t> directory_handle, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			if (!directory_handle)
				return STATUS_INVALID_PARAMETER;

			const auto name = attribute_name(cpu, object_attributes);
			const auto handle = open_namespace_object(std::make_shared<directory_host>(),
				name, desired_access);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			directory_handle.write(handle);

			THREAD_LOG_WARN("NtOpenDirectoryObject('{}') -> handle=0x{:X}: the directory is "
				"empty, because nothing here puts anything in one", name, handle);

			return STATUS_SUCCESS;
		});

	// A link opened here is made the same way, and points where the loader
	// expects the one it actually asks for -- KnownDllPath -- to point.
	state.redirect_ntzw(mod, "OpenSymbolicLinkObject",
		[attribute_name, open_namespace_object](vcpu& cpu, emu_object<std::uint64_t> link_handle,
			const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			if (!link_handle)
				return STATUS_INVALID_PARAMETER;

			const auto name = attribute_name(cpu, object_attributes);

			auto host = std::make_shared<symbolic_link_host>();
			host->target = system32_dir_narrow;

			// Windows spells a device path without the trailing separator.
			if (host->target.size() > 1 && host->target.back() == '\\')
				host->target.pop_back();

			const auto handle = open_namespace_object(std::move(host), name, desired_access);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			link_handle.write(handle);

			THREAD_LOG_WARN("NtOpenSymbolicLinkObject('{}') -> handle=0x{:X}: nothing here "
				"creates a link, so it points at System32", name, handle);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "QuerySymbolicLinkObject",
		[st = &state](vcpu&, const std::uint64_t link_handle,
			emu_object<_UNICODE_STRING> link_target,
			emu_object<std::uint32_t> returned_length) -> NTSTATUS
		{
			const auto host =
				st->sys_proc->handle_table().get_object<symbolic_link_host>(link_handle);

			if (!host)
			{
				THREAD_LOG_WARN("NtQuerySymbolicLinkObject: handle 0x{:X} is not a symbolic link",
					link_handle);
				return STATUS_OBJECT_TYPE_MISMATCH;
			}

			const auto target = widen_string(host->target);
			const auto needed = static_cast<std::uint16_t>(target.size() * sizeof(wchar_t));

			if (returned_length)
				returned_length.write(needed);

			if (!link_target)
				return STATUS_INVALID_PARAMETER;

			auto value = link_target.read();

			if (value.MaximumLength < needed || !value.Buffer)
				return STATUS_BUFFER_TOO_SMALL;

			link_target.space()->write_mem(guest_va(value.Buffer), target.data(), needed);

			value.Length = needed;
			link_target.write(value);

			THREAD_LOG_INFO("NtQuerySymbolicLinkObject(0x{:X}) -> '{}'", link_handle, host->target);

			return STATUS_SUCCESS;
		});
}
