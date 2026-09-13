#include "nt_object_ops.hpp"
#include "../win_kernel.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/string.hpp"
#include "../../../util/log.hpp"

namespace
{

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
}
