#include "nt_object_ops.hpp"
#include "../win_kernel.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../process_params.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/string.hpp"
#include "../../../util/log.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

namespace
{

constexpr std::size_t namespace_object_body_size = 0x10;

// OBJECT_DIRECTORY_INFORMATION, whose counted strings point back into the same buffer.
#pragma pack(push, 8)
struct object_directory_information_t
{
	_UNICODE_STRING name;
	_UNICODE_STRING type_name;
};
#pragma pack(pop)

// WDK types the kernel does not store, so not in the PDB; both are the same on each architecture.
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

	// Only four object types exist here and nothing ties one to an object, so the type a caller
	// asks for is logged rather than enforced: a mismatch it never made is worse than no check.
	state.redirect(mod, "ObReferenceObjectByPointer",
		[&objs = state.objs](vcpu&, const addr_t object,
			[[maybe_unused]] const std::uint32_t desired_access, const addr_t object_type,
			[[maybe_unused]] const std::uint8_t access_mode) -> NTSTATUS
		{
			if (!object)
				return STATUS_INVALID_PARAMETER;

			if (!objs.has_object(object))
				THREAD_LOG_WARN("ObReferenceObjectByPointer: 0x{:X} is not an object here, so "
					"the reference is not counted", object);
			else
				objs.reference_object(object);

			THREAD_LOG_INFO("ObReferenceObjectByPointer(object=0x{:X}, type=0x{:X})",
				object, object_type);

			return STATUS_SUCCESS;
		});

	auto deref = [&objs = state.objs](vcpu&, addr_t object) -> void
	{
		THREAD_LOG_INFO("ObfDereferenceObject(object=0x{:X})", object);
		objs.dereference_object(object);
	};

	state.redirect(mod, "ObfDereferenceObject", deref);
	state.redirect(mod, "ObfDereferenceObjectWithTag", deref);

	auto close_fn = [st = &state, sys_proc](vcpu& cpu, std::uint64_t handle) -> NTSTATUS
	{
		THREAD_LOG_INFO("NtClose(handle=0x{:X})", handle);

		// The last handle on a device is what tells its driver the open is over, so the two
		// requests real cleanup sends go out before the handle stops naming anything.
		if (const auto host = sys_proc->handle_table().get_object<file_host>(handle);
			host && host->is_device())
		{
			if (auto* const emulator = st->emulator())
			{
				for (const auto major : { irp_mj_cleanup, irp_mj_close })
				{
					emulator->dispatch_irp(cpu, {
						.major = major,
						.device_object = host->device_object,
						.file_object = host->file_object,
					});
				}
			}

			st->pool.free(host->file_object);
		}

		if (!sys_proc->handle_table().close_handle(handle))
		{
			THREAD_LOG_WARN("NtClose: invalid handle 0x{:X}", handle);
			return STATUS_INVALID_HANDLE;
		}

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "Close", close_fn);

	// A registration is kept and honoured: the pre callback runs on every handle open of an object
	// of the type it named, and the access it returns is the access the handle is made with.
	state.redirect(mod, "ObRegisterCallbacks",
		[st = &state](vcpu& cpu, emu_object<void> callback_registration,
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

			const std::uint8_t body[sizeof(addr_t)] = {};
			const auto handle = st->objs.create_object(0, body, sizeof(body), {},
				prot_rw | prot_supervisor);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			registration_handle.write(handle);

			THREAD_LOG_INFO("ObRegisterCallbacks(version={}, altitude='{}', {} operation(s)) "
				"-> 0x{:X}", reg.version, altitude, reg.operation_count, handle);

			for (std::uint16_t i = 0; i < reg.operation_count; ++i)
			{
				const emu_object<ob_operation_registration_t> op(space,
					reg.operation_registration + i * sizeof(ob_operation_registration_t));

				const auto entry = op.read();
				const auto type = space.read_mem<addr_t>(entry.object_type);

				ob_registration stored{};
				stored.registration = handle;
				stored.object_type = type;
				stored.operations = entry.operations;
				stored.pre = entry.pre_operation;
				stored.post = entry.post_operation;
				stored.context = reg.registration_context;

				{
					std::scoped_lock lock(st->ob_mtx_);
					st->ob_registrations.push_back(stored);
				}

				THREAD_LOG_INFO("  operation[{}]: type=0x{:X} (at 0x{:X}), operations=0x{:X}, "
					"pre=0x{:X}, post=0x{:X}", i, type, entry.object_type, entry.operations,
					entry.pre_operation, entry.post_operation);
			}

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "ObUnRegisterCallbacks",
		[st = &state](vcpu&, const addr_t registration_handle)
		{
			std::size_t removed = 0;

			{
				std::scoped_lock lock(st->ob_mtx_);

				std::erase_if(st->ob_registrations, [&](const ob_registration& r)
				{
					if (r.registration != registration_handle)
						return false;

					++removed;
					return true;
				});
			}

			THREAD_LOG_INFO("ObUnRegisterCallbacks(0x{:X}): {} operation(s) dropped",
				registration_handle, removed);
		});

	// Nothing here builds a type index table, so the kind comes from the host object instead.
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

	state.redirect(mod, "ObOpenObjectByPointer",
		[st = &state](vcpu& cpu, const addr_t object, const std::uint32_t handle_attributes,
			const addr_t passed_access_state, const std::uint32_t desired_access,
			const addr_t object_type, const std::uint8_t access_mode,
			emu_object<std::uint64_t> handle) -> NTSTATUS
		{
			if (!handle)
				return STATUS_INVALID_PARAMETER;

			auto access = desired_access;
			addr_t type = 0;

			if (st->objs.get_object<thread_object>(object))
				type = st->object_type_pointer("PsThreadType");

			if (type)
			{
				access = st->ob_pre_handle(cpu, object, type, ob_operation_handle_create, access);

				if (!access)
					return STATUS_ACCESS_DENIED;
			}

			st->objs.reference_object(object);
			const auto value = st->sys_proc->handle_table().create_handle(object, access);

			if (type)
				st->ob_post_handle(cpu, object, type, ob_operation_handle_create, STATUS_SUCCESS, access);

			handle.write(value);

			THREAD_LOG_INFO("ObOpenObjectByPointer(0x{:X}, attributes=0x{:X}, access_state=0x{:X}, "
				"access=0x{:X}, type=0x{:X}, mode={}) -> handle=0x{:X}",
				object, handle_attributes, passed_access_state, desired_access, object_type,
				access_mode, value);

			return STATUS_SUCCESS;
		});

	// There is one handle table, hanging off the system process, and every process here shares it.
	state.redirect(mod, "ObReferenceProcessHandleTable",
		[](vcpu&, emu_object<_EPROCESS> process) -> addr_t
		{
			const auto table = process
				? guest_va(process.field(&_EPROCESS::ObjectTable).read()) : 0;

			THREAD_LOG_INFO("ObReferenceProcessHandleTable(0x{:X}) -> 0x{:X}",
				process.address(), table);

			return table;
		});

	// Nothing here calls back into the guest, so null says the walk finished without a match.
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

	// Nothing builds the directories these names would hang off, so opening one makes it.
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
		const auto key = object_namespace_key(name);

		if (const auto existing = st->objs.lookup_named_object(key))
			return st->sys_proc->handle_table().create_handle(existing, desired_access);

		const std::array<std::uint8_t, namespace_object_body_size> body{};
		const auto addr = st->objs.create_object(0, body.data(), body.size(), std::move(host),
			prot_rw | prot_supervisor);

		if (!addr)
			return 0;

		st->objs.register_named_object(key, addr);

		return st->sys_proc->handle_table().create_handle(addr, desired_access);
	};

	// A name resolved against the namespace, which is how a walk over \Driver opens what it
	// found there.
	state.redirect(mod, "ObOpenObjectByName",
		[st = &state, attribute_name](vcpu& cpu, emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			const addr_t object_type, [[maybe_unused]] const std::uint8_t access_mode,
			[[maybe_unused]] const addr_t passed_access_state,
			const std::uint32_t desired_access, [[maybe_unused]] const addr_t parse_context,
			emu_object<std::uint64_t> handle) -> NTSTATUS
		{
			if (!object_attributes || !handle)
				return STATUS_INVALID_PARAMETER;

			const auto name = attribute_name(cpu, object_attributes);
			const auto addr = st->objs.lookup_named_object(object_namespace_key(name));

			if (!addr)
			{
				THREAD_LOG_WARN("ObOpenObjectByName('{}'): nothing by that name", name);
				return STATUS_OBJECT_NAME_NOT_FOUND;
			}

			st->objs.reference_object(addr);
			const auto value = st->sys_proc->handle_table().create_handle(addr, desired_access);

			handle.write(value);

			THREAD_LOG_INFO("ObOpenObjectByName('{}', type=0x{:X}, access=0x{:X}) -> handle=0x{:X}",
				name, object_type, desired_access, value);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "OpenDirectoryObject",
		[attribute_name, open_namespace_object](vcpu& cpu,
			emu_object<std::uint64_t> directory_handle, const std::uint32_t desired_access,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes) -> NTSTATUS
		{
			if (!directory_handle)
				return STATUS_INVALID_PARAMETER;

			const auto name = attribute_name(cpu, object_attributes);

			auto host = std::make_shared<directory_host>();
			host->name = name;

			const auto handle = open_namespace_object(std::move(host), name, desired_access);

			if (!handle)
				return STATUS_INSUFFICIENT_RESOURCES;

			directory_handle.write(handle);

			THREAD_LOG_INFO("NtOpenDirectoryObject('{}') -> handle=0x{:X}", name, handle);

			return STATUS_SUCCESS;
		});

	// A directory is enumerated from what is actually registered under it, so a walk over one
	// sees the objects that exist rather than an empty answer.
	state.redirect_ntzw(mod, "QueryDirectoryObject",
		[st = &state](vcpu& cpu, const std::uint64_t directory_handle, const addr_t buffer,
			const std::uint32_t length, const std::uint8_t return_single_entry,
			const std::uint8_t restart_scan, emu_object<std::uint32_t> context,
			emu_object<std::uint32_t> return_length) -> NTSTATUS
		{
			const auto host =
				st->sys_proc->handle_table().get_object<directory_host>(directory_handle);

			if (!host)
			{
				THREAD_LOG_WARN("NtQueryDirectoryObject: handle 0x{:X} is not a directory",
					directory_handle);
				return STATUS_INVALID_HANDLE;
			}

			const auto prefix = object_namespace_key(host->name) + "/";
			const auto children = st->objs.child_names(prefix);

			std::uint32_t index = 0;

			if (!restart_scan && context)
				index = context.read();

			if (index > children.size())
				index = static_cast<std::uint32_t>(children.size());

			const auto type_of = [st](const std::string_view name) -> std::u16string_view
			{
				const auto addr = st->objs.lookup_named_object(name);

				if (!addr)
					return u"Unknown";

				if (st->objs.get_object<directory_host>(addr))
					return u"Directory";
				if (st->objs.get_object<driver_object_host>(addr))
					return u"Driver";
				if (st->objs.get_object<section_host>(addr))
					return u"Section";
				if (st->objs.get_object<symbolic_link_host>(addr))
					return u"SymbolicLink";
				if (st->objs.get_object<file_host>(addr))
					return u"File";
				if (st->objs.get_object<device_host>(addr))
					return u"Device";

				return u"Unknown";
			};

			auto& space = *cpu.curr_addr_space();

			// The layout is the one the kernel builds: an array of OBJECT_DIRECTORY_INFORMATION with
			// a zeroed terminator after the last entry, and every name and type string in one run
			// after the array, the structures' buffers pointing into it. A caller walks the array
			// by its fixed size and stops on the zeroed entry, so the strings must not sit between
			// the structures -- a walk that steps by the structure size would then read a
			// structure out of the middle of a string.
			constexpr auto header = sizeof(object_directory_information_t);

			struct directory_entry
			{
				std::u16string name;
				std::u16string type;
			};

			std::vector<directory_entry> chosen;
			std::size_t total = header;

			for (std::size_t i = index; i < children.size(); ++i)
			{
				directory_entry entry{};
				entry.name = widen_string(children[i]);
				entry.type = std::u16string(type_of(prefix + children[i]));

				const auto add = header + entry.name.size() * 2 + 2 + entry.type.size() * 2 + 2;

				if (total + add > length)
					break;

				chosen.push_back(std::move(entry));
				total += add;

				if (return_single_entry)
					break;
			}

			const auto next = index + static_cast<std::uint32_t>(chosen.size());
			const auto more = next < children.size();

			if (total > length)
				return STATUS_BUFFER_TOO_SMALL;

			std::vector<std::uint8_t> out(total, 0);

			auto string_at = header * (chosen.size() + 1);

			for (std::size_t i = 0; i < chosen.size(); ++i)
			{
				const auto& entry = chosen[i];
				auto* const info = reinterpret_cast<object_directory_information_t*>(
					out.data() + i * header);

				const auto name_bytes = static_cast<std::uint16_t>(entry.name.size() * 2);
				const auto type_bytes = static_cast<std::uint16_t>(entry.type.size() * 2);

				info->name.Length = name_bytes;
				info->name.MaximumLength = static_cast<std::uint16_t>(name_bytes + 2);
				info->name.Buffer = guest_ptr<char16_t>(buffer + string_at);

				std::memcpy(out.data() + string_at, entry.name.data(), name_bytes);
				string_at += name_bytes + 2;

				info->type_name.Length = type_bytes;
				info->type_name.MaximumLength = static_cast<std::uint16_t>(type_bytes + 2);
				info->type_name.Buffer = guest_ptr<char16_t>(buffer + string_at);

				std::memcpy(out.data() + string_at, entry.type.data(), type_bytes);
				string_at += type_bytes + 2;
			}

			if (return_length)
				return_length.write(static_cast<std::uint32_t>(out.size()));

			if (context)
				context.write(next);

			space.write_mem(buffer, out.data(), out.size());

			THREAD_LOG_INFO("NtQueryDirectoryObject('{}', buffer={}/{}, single={}): {} of {} "
				"entry(s)", host->name, buffer, length, return_single_entry != 0,
				chosen.size(), children.size());

			if (chosen.empty() && index >= children.size())
				return STATUS_NO_MORE_ENTRIES;

			return more ? STATUS_MORE_ENTRIES : STATUS_SUCCESS;
		});

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
			const auto needed = static_cast<std::uint16_t>(target.size() * sizeof(char16_t));

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
