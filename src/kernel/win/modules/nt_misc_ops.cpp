#include "nt_misc_ops.hpp"
#include "../win_kernel.hpp"
#include "../driver.hpp"
#include "../pool.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../thread.hpp"
#include "../types.hpp"
#include "../../../emu/guest_call.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <cstring>
#include <vector>

namespace
{

// A WDK type the kernel never stores, so not in the PDB; layout taken from the register call.
constexpr std::size_t bugcheck_record_callback_routine = 0x10;
constexpr std::size_t bugcheck_record_component = 0x18;
constexpr std::size_t bugcheck_record_checksum = 0x20;
constexpr std::size_t bugcheck_record_reason = 0x28;
constexpr std::size_t bugcheck_record_state = 0x2C;

constexpr std::uint8_t bugcheck_record_registered = 1;

// ExCreateCallback's body: Call at 0, list head at 0x10, AllowMultipleCallbacks at 0x20.
constexpr std::size_t callback_object_size = 0x38;
constexpr std::size_t callback_object_list_head = 0x10;
constexpr std::size_t callback_object_allow_multiple = 0x20;
constexpr std::uint32_t callback_object_signature = 0x6C6C6143;

struct callback_host final : win_object
{
	struct registration
	{
		addr_t function = 0;
		addr_t context = 0;
	};

	std::vector<registration> registrations;
	bool allow_multiple = false;
};

struct callback_registration_host final : win_object
{
	addr_t callback_object_addr = 0;
};

// A triage dump: signature, the machine that made it, and where the consumer looks for each
// part. Recovered from what reads one back, so the offsets are named only where they are used.
constexpr std::uint32_t dump_signature = 0x45474150;   // 'PAGE'
constexpr std::uint32_t dump_valid_dump = 0x34365544;  // 'DU64'
constexpr std::uint32_t dump_end_signature = 0x444D5054;
constexpr std::uint32_t dump_buffer_size = 0x40000;
constexpr std::size_t dump_context_off = 840;
constexpr std::size_t dump_context_pc_off = 3856;

// A WDK enum; the kernel does not store one, so it is not in the PDB.
enum token_information_class : std::uint32_t
{
	token_privileges      = 3,
	token_integrity_level = 25,
};

// SID_AND_ATTRIBUTES::Attributes, and the parts of S-1-16-12288.
enum sid_attributes : std::uint32_t
{
	se_group_integrity = 0x00000020,
};

constexpr std::uint8_t security_mandatory_label_authority = 16;
constexpr std::uint32_t security_mandatory_high_rid = 12288;

// Recovered from the binary -- SeRegisterImageVerificationCallback has no documented prototype.
enum image_verification_type : std::uint32_t
{
	image_verification_driver_info = 1,
	image_verification_block_info  = 4,
};

constexpr std::uint32_t image_verification_subtype(const image_verification_type type)
{
	return type == image_verification_driver_info ? 0u : 1u;
}

}

// The rest of what a driver reaches for on its way up; none of these callbacks is ever invoked.
void modules::register_ntoskrnl_misc_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "KeRegisterBugCheckReasonCallback",
		[](vcpu& cpu, emu_object<void> callback_record, const addr_t callback_routine,
			const std::uint32_t reason, const addr_t component) -> bool
		{
			auto& space = *cpu.curr_addr_space();

			const auto base = callback_record.address();
			const auto state_at = base + bugcheck_record_state;
			const auto name = component ? guest::read_string(space, component) : std::string{};

			if (space.read_mem<std::uint8_t>(state_at))
			{
				THREAD_LOG_WARN("KeRegisterBugCheckReasonCallback: record 0x{:X} is already registered",
					base);
				return false;
			}

			space.write_mem<addr_t>(base + bugcheck_record_callback_routine, callback_routine);
			space.write_mem<addr_t>(base + bugcheck_record_component, component);
			space.write_mem<addr_t>(base + bugcheck_record_checksum,
				callback_routine + reason + component);
			space.write_mem<std::uint32_t>(base + bugcheck_record_reason, reason);
			space.write_mem<std::uint8_t>(state_at, bugcheck_record_registered);

			THREAD_LOG_INFO("KeRegisterBugCheckReasonCallback(record=0x{:X}, routine=0x{:X}, reason={}, component='{}') -> true",
				base, callback_routine, reason, name);

			return true;
		});

	state.redirect(mod, "KeDeregisterBugCheckReasonCallback",
		[](vcpu& cpu, emu_object<void> callback_record) -> bool
		{
			auto& space = *cpu.curr_addr_space();
			const auto state_at = callback_record.address() + bugcheck_record_state;

			const bool registered =
				space.read_mem<std::uint8_t>(state_at) == bugcheck_record_registered;

			if (registered)
				space.write_mem<std::uint8_t>(state_at, 0);

			THREAD_LOG_INFO("KeDeregisterBugCheckReasonCallback(record=0x{:X}) -> {}",
				callback_record.address(), registered);

			return registered;
		});

	state.redirect(mod, "ExCreateCallback",
		[st](vcpu& cpu, emu_object<addr_t> callback_object_out,
			emu_object<_OBJECT_ATTRIBUTES> object_attributes,
			const bool create, const bool allow_multiple_callbacks) -> NTSTATUS
		{
			auto& space = *cpu.curr_addr_space();

			const emu_object<_UNICODE_STRING> object_name(space, object_attributes
				? guest_va(object_attributes.field(&_OBJECT_ATTRIBUTES::ObjectName).read())
				: 0);
			const auto name = win::read_unicode_string(object_name);

			const auto narrow_name = narrow_wstring(name);

			// Only an unnamed open has nothing to look up and nothing to make.
			if (narrow_name.empty() && !create)
			{
				THREAD_LOG_WARN("ExCreateCallback(create=false): no name to open");
				return STATUS_UNSUCCESSFUL;
			}

			const auto key = narrow_name.empty()
				? std::string{}
				: object_namespace_key(narrow_name);

			if (!key.empty())
			{
				if (const auto existing = st->objs.lookup_named_object(key);
					existing && st->objs.get_object<callback_host>(existing))
				{
					callback_object_out.write(existing);

					THREAD_LOG_INFO("ExCreateCallback('{}', create={}) -> 0x{:X} (existing)",
						narrow_name, create, existing);

					return STATUS_SUCCESS;
				}
			}

			auto host = std::make_shared<callback_host>();
			host->allow_multiple = allow_multiple_callbacks;

			const std::vector<std::uint8_t> body(callback_object_size, 0);
			const auto addr = st->objs.create_object(0, body.data(), body.size(),
				std::move(host), prot_rw | prot_supervisor);

			if (!addr)
			{
				THREAD_LOG_ERR("ExCreateCallback: out of memory");
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			const auto list_head = addr + callback_object_list_head;

			space.write_mem<std::uint32_t>(addr, callback_object_signature);
			space.write_mem<addr_t>(list_head, list_head);
			space.write_mem<addr_t>(list_head + sizeof(addr_t), list_head);
			space.write_mem<std::uint8_t>(addr + callback_object_allow_multiple,
				allow_multiple_callbacks ? 1 : 0);

			// Named, so the next open of the same name is the same object rather than a second one.
			if (!key.empty())
				st->objs.register_named_object(key, addr);

			callback_object_out.write(addr);

			THREAD_LOG_INFO("ExCreateCallback('{}', create={}, allow_multiple={}) -> 0x{:X}",
				narrow_name, create, allow_multiple_callbacks, addr);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "ExRegisterCallback",
		[st](vcpu&, const addr_t callback_object_addr, const addr_t callback_function,
			const addr_t callback_context) -> addr_t
		{
			const auto object = st->objs.get_object<callback_host>(callback_object_addr);

			if (!object)
			{
				THREAD_LOG_WARN("ExRegisterCallback: 0x{:X} is not a callback object",
					callback_object_addr);
				return 0;
			}

			if (!object->registrations.empty() && !object->allow_multiple)
			{
				THREAD_LOG_WARN("ExRegisterCallback: 0x{:X} does not allow multiple callbacks",
					callback_object_addr);
				return 0;
			}

			auto host = std::make_shared<callback_registration_host>();
			host->callback_object_addr = callback_object_addr;

			const std::uint8_t body[sizeof(addr_t)] = {};
			const auto addr = st->objs.create_object(0, body, sizeof(body),
				std::move(host), prot_rw | prot_supervisor);

			if (!addr)
			{
				THREAD_LOG_ERR("ExRegisterCallback: out of memory");
				return 0;
			}

			object->registrations.push_back({callback_function, callback_context});

			THREAD_LOG_INFO("ExRegisterCallback(object=0x{:X}, function=0x{:X}, context=0x{:X}) -> 0x{:X}",
				callback_object_addr, callback_function, callback_context, addr);

			return addr;
		});

	state.redirect(mod, "IoCreateDevice",
		[st](vcpu& cpu, emu_object<_DRIVER_OBJECT> driver_object,
			const std::uint32_t device_extension_size,
			emu_object<_UNICODE_STRING> device_name,
			const std::uint32_t device_type, const std::uint32_t device_characteristics,
			const bool exclusive, emu_object<addr_t> device_object_out) -> NTSTATUS
		{
			if (!driver_object || !device_object_out)
				return STATUS_INVALID_PARAMETER;

			auto& space = *cpu.curr_addr_space();
			const auto name = win::read_unicode_string(device_name);

			// A driver casts the extension to its own structure, so align it to 8.
			const auto extension_size = (device_extension_size + 7) & ~std::uint32_t{7};
			const auto body_size = sizeof(_DEVICE_OBJECT) + extension_size;

			auto host = std::make_shared<device_host>();
			host->driver_object = driver_object.address();
			host->name = narrow_wstring(name);

			const std::vector<std::uint8_t> body(body_size, 0);
			const auto addr = st->objs.create_object(0, body.data(), body.size(),
				std::move(host), prot_rw | prot_supervisor);

			if (!addr)
			{
				THREAD_LOG_ERR("IoCreateDevice: out of memory for {} bytes", body_size);
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			_DEVICE_OBJECT device{};
			device.Type = io_type_device;
			device.Size = static_cast<unsigned short>(body_size);
			device.ReferenceCount = 1;
			device.DriverObject = guest_ptr<_DRIVER_OBJECT>(driver_object.address());
			device.DeviceType = device_type;
			device.Characteristics = device_characteristics;
			device.StackSize = 1;

			// The driver clears DO_DEVICE_INITIALIZING itself; one that forgets is a real bug.
			device.Flags = do_device_initializing | (exclusive ? do_exclusive : 0);

			if (device_extension_size)
				device.DeviceExtension = guest_ptr<void>(addr + sizeof(_DEVICE_OBJECT));

			auto head = driver_object.field(&_DRIVER_OBJECT::DeviceObject);
			device.NextDevice = head.read();

			emu_object<_DEVICE_OBJECT>(space, addr).write(device);
			head.write(guest_ptr<_DEVICE_OBJECT>(addr));
			device_object_out.write(addr);

			// An unnamed device is reachable only through a pointer the driver hands out; a
			// named one is what NtCreateFile resolves, so only that one joins the namespace.
			st->register_device(narrow_wstring(name), addr);

			THREAD_LOG_INFO("IoCreateDevice(driver=0x{:X}, extension_size=0x{:X}, name='{}', type=0x{:X}, characteristics=0x{:X}, exclusive={}) -> 0x{:X}",
				driver_object.address(), device_extension_size, narrow_wstring(name),
				device_type, device_characteristics, exclusive, addr);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "IoDeleteDevice",
		[st](vcpu& cpu, emu_object<_DEVICE_OBJECT> device_object)
		{
			if (!device_object)
				return;

			const auto host = st->objs.get_object<device_host>(device_object.address());

			if (!host)
			{
				THREAD_LOG_WARN("IoDeleteDevice: 0x{:X} is not a device object",
					device_object.address());
				return;
			}

			auto& space = *cpu.curr_addr_space();
			const auto next = device_object.field(&_DEVICE_OBJECT::NextDevice).read();

			emu_object<_DRIVER_OBJECT> driver(space, host->driver_object);
			auto link = driver.field(&_DRIVER_OBJECT::DeviceObject);

			while (link.address())
			{
				const auto entry = guest_va(link.read());

				if (!entry)
				{
					THREAD_LOG_WARN("IoDeleteDevice: 0x{:X} is not on driver 0x{:X}'s device list",
						device_object.address(), host->driver_object);
					break;
				}

				if (entry == device_object.address())
				{
					link.write(next);
					break;
				}

				link = emu_object<_DEVICE_OBJECT>(space, entry)
					.field(&_DEVICE_OBJECT::NextDevice);
			}

			st->unregister_device_name(host->name);
			st->objs.dereference_object(device_object.address());

			THREAD_LOG_INFO("IoDeleteDevice(0x{:X})", device_object.address());
		});

	state.redirect(mod, "IoCreateSymbolicLink",
		[st](vcpu&, emu_object<_UNICODE_STRING> symbolic_link_name,
			emu_object<_UNICODE_STRING> device_name) -> NTSTATUS
		{
			const auto link = narrow_wstring(win::read_unicode_string(symbolic_link_name));
			const auto target = narrow_wstring(win::read_unicode_string(device_name));

			st->register_device_link(link, target);

			THREAD_LOG_INFO("IoCreateSymbolicLink('{}' -> '{}')", link, target);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "IoDeleteSymbolicLink",
		[st](vcpu&, emu_object<_UNICODE_STRING> symbolic_link_name) -> NTSTATUS
		{
			const auto link = narrow_wstring(win::read_unicode_string(symbolic_link_name));

			st->unregister_device_name(link);

			THREAD_LOG_INFO("IoDeleteSymbolicLink('{}')", link);

			return STATUS_SUCCESS;
		});

	// Completing a request pops every stack location off it, which is what leaves CurrentLocation
	// past StackCount -- and that is how the io manager tells a completed request from one the
	// driver kept. A completion routine would run here; nothing sets one on a request issued here.
	state.redirect(mod, "IofCompleteRequest",
		[](vcpu& cpu, const addr_t irp, const std::int8_t priority_boost)
		{
			const emu_object<_IRP> request(*cpu.curr_addr_space(), irp);

			if (!request)
				return;

			const auto stack_count = request.field(&_IRP::StackCount).read();
			request.field(&_IRP::CurrentLocation).write(stack_count + 1);

			const auto io_status = request.field(&_IRP::IoStatus).read();

			THREAD_LOG_INFO("IofCompleteRequest(irp=0x{:X}, priority_boost={}) -> status=0x{:X}, "
				"information={}", irp, priority_boost,
				static_cast<std::uint32_t>(io_status.Status), io_status.Information);
		});

	state.redirect(mod, "IoRegisterShutdownNotification",
		[](vcpu&, emu_object<_DEVICE_OBJECT> device_object) -> NTSTATUS
		{
			if (!device_object)
				return STATUS_INVALID_PARAMETER;

			auto flags = device_object.field(&_DEVICE_OBJECT::Flags);
			flags.write(flags.read() | do_shutdown_registered);

			THREAD_LOG_INFO("IoRegisterShutdownNotification(0x{:X})", device_object.address());

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "IoRegisterPlugPlayNotification",
		[st](vcpu&, const std::uint32_t event_category,
			const std::uint32_t event_category_flags, const addr_t event_category_data,
			const addr_t driver_object, const addr_t callback_routine,
			const addr_t context, emu_object<addr_t> notification_entry) -> NTSTATUS
		{
			if (!notification_entry)
				return STATUS_INVALID_PARAMETER;

			const auto entry = st->pool.allocate(sizeof(addr_t), pool_tag("PnPN"), true);

			if (!entry)
			{
				THREAD_LOG_ERR("IoRegisterPlugPlayNotification: out of pool");
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			notification_entry.write(entry);

			THREAD_LOG_INFO("IoRegisterPlugPlayNotification(category={}, flags=0x{:X}, data=0x{:X}, driver=0x{:X}, callback=0x{:X}, context=0x{:X}) -> 0x{:X}",
				event_category, event_category_flags, event_category_data, driver_object,
				callback_routine, context, entry);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "IoUnregisterPlugPlayNotificationEx",
		[st](vcpu&, const addr_t notification_entry) -> NTSTATUS
		{
			THREAD_LOG_INFO("IoUnregisterPlugPlayNotificationEx(0x{:X})", notification_entry);

			st->pool.free(notification_entry);

			return STATUS_SUCCESS;
		});

	// An empty list is a double null, not a null pointer: that is what the caller walks and frees.
	state.redirect(mod, "IoGetDeviceInterfaces",
		[st](vcpu&, const addr_t interface_class_guid,
			const addr_t physical_device_object, const std::uint32_t flags,
			emu_object<addr_t> symbolic_link_list) -> NTSTATUS
		{
			if (!symbolic_link_list)
				return STATUS_INVALID_PARAMETER;

			const auto list = st->pool.allocate(2 * sizeof(char16_t),
				pool_tag("IoDi"), true);

			if (!list)
			{
				THREAD_LOG_ERR("IoGetDeviceInterfaces: out of pool");
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			symbolic_link_list.write(list);

			THREAD_LOG_INFO("IoGetDeviceInterfaces(guid=0x{:X}, pdo=0x{:X}, flags=0x{:X}) -> empty list at 0x{:X}",
				interface_class_guid, physical_device_object, flags, list);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "IoWMIOpenBlock",
		[](vcpu&, emu_object<_GUID> guid, const std::uint32_t desired_access,
			emu_object<addr_t> data_block_object) -> NTSTATUS
		{
			const auto g = guid ? guid.read() : _GUID{};

			THREAD_LOG_WARN("IoWMIOpenBlock({{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}, access=0x{:X}, out=0x{:X}): no WMI block is registered",
				g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
				g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7],
				desired_access, data_block_object.address());

			return STATUS_WMI_GUID_NOT_FOUND;
		});

	state.redirect(mod, "HalAcpiGetTableEx",
		[](vcpu&, const addr_t loader_block, const std::uint32_t signature,
			const std::uint32_t oem_id, const std::uint32_t oem_table_id) -> addr_t
		{
			// A table signature is four characters, passed as a FourCC.
			const char name[5] = {
				static_cast<char>(signature & 0xFF),
				static_cast<char>((signature >> 8) & 0xFF),
				static_cast<char>((signature >> 16) & 0xFF),
				static_cast<char>((signature >> 24) & 0xFF),
				'\0'
			};

			THREAD_LOG_WARN("HalAcpiGetTableEx(loader_block=0x{:X}, signature='{}', oem_id=0x{:X}, oem_table_id=0x{:X}): there is no ACPI here",
				loader_block, name, oem_id, oem_table_id);

			return 0;
		});

	// The buffer is left alone rather than filled with a config space a driver would act on.
	state.redirect(mod, "HalGetBusDataByOffset",
		[](vcpu&, const std::uint32_t bus_data_type, const std::uint32_t bus_number,
			const std::uint32_t slot_number, const addr_t buffer,
			const std::uint32_t offset, const std::uint32_t length) -> std::uint32_t
		{
			THREAD_LOG_WARN("HalGetBusDataByOffset(type={}, bus={}, slot={}, buffer=0x{:X}, offset={}, length={}): no bus -> 0 bytes",
				bus_data_type, bus_number, slot_number, buffer, offset, length);

			return 0;
		});

	// Not an ntoskrnl export -- imported from hal, which is not mapped; binds by PDB symbol.
	state.redirect(mod, "HalPutDmaAdapter",
		[st](vcpu&, const addr_t dma_adapter)
		{
			THREAD_LOG_INFO("HalPutDmaAdapter(0x{:X})", dma_adapter);
			st->objs.dereference_object(dma_adapter);
		});

	state.redirect(mod, "SeQueryInformationToken",
		[st](vcpu& cpu, const addr_t token, const std::uint32_t token_information_class,
			emu_object<addr_t> token_information) -> NTSTATUS
		{
			if (!token_information)
				return STATUS_INVALID_PARAMETER;

			auto& space = *cpu.curr_addr_space();

			if (token_information_class == token_integrity_level)
			{
				constexpr auto size = sizeof(_SID_AND_ATTRIBUTES) + sizeof(_SID);
				const auto buffer = st->pool.allocate(size, pool_tag("Se  "), true);

				if (!buffer)
					return STATUS_INSUFFICIENT_RESOURCES;

				const auto sid_addr = buffer + sizeof(_SID_AND_ATTRIBUTES);

				_SID sid{};
				sid.Revision = 1;
				sid.SubAuthorityCount = 1;
				sid.IdentifierAuthority.Value[5] = security_mandatory_label_authority;
				sid.SubAuthority[0] = security_mandatory_high_rid;

				emu_object<_SID>(space, sid_addr).write(sid);

				_SID_AND_ATTRIBUTES label{};
				label.Sid = guest_ptr<void>(sid_addr);
				label.Attributes = se_group_integrity;

				emu_object<_SID_AND_ATTRIBUTES>(space, buffer).write(label);
				token_information.write(buffer);

				THREAD_LOG_INFO("SeQueryInformationToken(token=0x{:X}, TokenIntegrityLevel) -> 0x{:X} (S-1-16-{})",
					token, buffer, security_mandatory_high_rid);

				return STATUS_SUCCESS;
			}

			if (token_information_class == token_privileges)
			{
				const auto buffer = st->pool.allocate(sizeof(std::uint32_t),
					pool_tag("Se  "), true);

				if (!buffer)
					return STATUS_INSUFFICIENT_RESOURCES;

				token_information.write(buffer);

				THREAD_LOG_INFO("SeQueryInformationToken(token=0x{:X}, TokenPrivileges) -> 0x{:X} (count=0)",
					token, buffer);

				return STATUS_SUCCESS;
			}

			THREAD_LOG_WARN("SeQueryInformationToken(token=0x{:X}, class={}): unhandled class",
				token, token_information_class);

			return STATUS_INVALID_INFO_CLASS;
		});

	state.redirect(mod, "SeRegisterImageVerificationCallback",
		[st](vcpu&, const std::uint32_t callback_type, const std::uint32_t callback_subtype,
			const addr_t callback_function, const addr_t callback_context,
			const addr_t reserved, emu_object<addr_t> callback_handle) -> NTSTATUS
		{
			if (callback_type != image_verification_driver_info
				&& callback_type != image_verification_block_info)
				return STATUS_INVALID_PARAMETER_1;

			if (callback_subtype != image_verification_subtype(
					static_cast<image_verification_type>(callback_type)))
				return STATUS_INVALID_PARAMETER_2;

			if (reserved)
				return STATUS_INVALID_PARAMETER_5;

			auto host = std::make_shared<callback_registration_host>();

			const std::uint8_t body[sizeof(addr_t)] = {};
			const auto handle = st->objs.create_object(0, body, sizeof(body),
				std::move(host), prot_rw | prot_supervisor);

			if (!handle)
				return STATUS_NO_MEMORY;

			callback_handle.write(handle);

			THREAD_LOG_INFO("SeRegisterImageVerificationCallback(type={}, subtype={}, function=0x{:X}, context=0x{:X}) -> 0x{:X}",
				callback_type, callback_subtype, callback_function, callback_context, handle);

			return STATUS_SUCCESS;
		});

	// The out parameter is cleared first, which is the order the real one does it in.
	state.redirect(mod, "ObReferenceObjectByName",
		[](vcpu&, emu_object<_UNICODE_STRING> object_name, const std::uint32_t attributes,
			const addr_t access_state, const std::uint32_t desired_access,
			const addr_t object_type, const std::uint8_t access_mode,
			const addr_t parse_context, emu_object<addr_t> object) -> NTSTATUS
		{
			if (object)
				object.write(0);

			const auto name = win::read_unicode_string(object_name);

			if (name.empty())
				return STATUS_OBJECT_NAME_INVALID;

			THREAD_LOG_WARN("ObReferenceObjectByName('{}', attributes=0x{:X}, desired_access=0x{:X}, type=0x{:X}, access_mode={}, parse_context=0x{:X}): nothing here has a name",
				narrow_wstring(name), attributes, desired_access, object_type,
				access_mode, parse_context);

			return STATUS_OBJECT_NAME_NOT_FOUND;
		});

	state.redirect(mod, "RtlPcToFileHeader",
		[st](vcpu& cpu, const addr_t pc_value, emu_object<addr_t> base_of_image) -> addr_t
		{
			const auto t = cpu.thread();
			auto proc = t ? t->proc() : nullptr;

			if (!proc)
				proc = st->sys_proc;

			auto m = proc->find_module_by_addr(pc_value);

			// A kernel address belongs to a module of the system process even when the caller
			// is a user thread, whose own list holds only its user modules.
			if (!m && proc != st->sys_proc)
				m = st->sys_proc->find_module_by_addr(pc_value);

			const addr_t base = m ? m->addr : 0;

			// Written on every path and not tested for null, because the real one does neither.
			base_of_image.write(base);

			THREAD_LOG_INFO("RtlPcToFileHeader(pc=0x{:X}) -> 0x{:X} ({})",
				pc_value, base, m ? m->name : "no module");

			return base;
		});

	// A tail call, so the broadcast function's result reaches the caller unchanged.
	state.redirect(mod, "KeIpiGenericCall",
		[](vcpu& cpu, const addr_t broadcast_function, const std::uint64_t context)
		{
			if (!broadcast_function)
			{
				THREAD_LOG_ERR("KeIpiGenericCall: null broadcast function");
				return;
			}

			THREAD_LOG_WARN("KeIpiGenericCall(0x{:X}, context=0x{:X}): nothing here holds the "
				"other cpus still, so it runs on this one alone",
				broadcast_function, context);

			const std::uint64_t args[] = { context };
			guest_tail_call(cpu, broadcast_function, args);
		});

	// A triage dump is undocumented, and a length claiming the buffer was filled is worse.
	// A triage dump header, which the caller reads back rather than writes anywhere. Every
	// offset below is recovered from what a consumer expects to find, not from a published
	// layout, which is why they are numbers and not a struct.
	state.redirect(mod, "KeCapturePersistentThreadState",
		[st, m = &mod](vcpu& cpu, const addr_t context, const addr_t thread,
			const std::uint32_t bugcheck_code, const std::uint64_t p1, const std::uint64_t p2,
			const std::uint64_t p3, const std::uint64_t p4, const addr_t buffer) -> std::uint32_t
		{
			THREAD_LOG_INFO("KeCapturePersistentThreadState(context=0x{:X}, thread=0x{:X}, "
				"bugcheck=0x{:X}, params=[0x{:X}, 0x{:X}, 0x{:X}, 0x{:X}], buffer=0x{:X})",
				context, thread, bugcheck_code, p1, p2, p3, p4, buffer);

			if (!buffer)
				return 0;

			auto& space = *cpu.curr_addr_space();

			std::vector<std::uint8_t> dump(dump_buffer_size, 0);
			auto* const buf = dump.data();

			const auto put32 = [buf](const std::size_t at, const std::uint32_t v)
			{
				std::memcpy(buf + at, &v, sizeof(v));
			};

			const auto put64 = [buf](const std::size_t at, const std::uint64_t v)
			{
				std::memcpy(buf + at, &v, sizeof(v));
			};

			put32(0, dump_signature);
			put32(4, dump_valid_dump);
			put32(12, st->nt_build_number);

			const auto owner = thread
				? thread
				: (cpu.thread() ? std::dynamic_pointer_cast<win_thread>(cpu.thread())->ethread()
					.address() : 0);

			if (owner)
			{
				const auto process = space.read_mem<addr_t>(owner
					+ offsetof(_KTHREAD, ApcState) + offsetof(_KAPC_STATE, Process));

				if (process)
					put64(16, space.read_mem<std::uint64_t>(process
						+ offsetof(_KPROCESS, DirectoryTableBase)) & ~0xFFFull);
			}

			if (const auto pfn = m->find_symbol("MmPfnDatabase"))
				put64(24, space.read_mem<std::uint64_t>(*pfn));

			put64(32, st->loaded_module_list.address());
			put64(40, st->active_process_list.address());

			put32(48, win_target::image_machine);
			put32(52, 1);

			put32(56, bugcheck_code);
			put64(64, p1);
			put64(72, p2);
			put64(80, p3);
			put64(88, p4);

			if (context)
			{
				space.read_mem(context, buf + dump_context_off, sizeof(_CONTEXT));
				put64(dump_context_pc_off,
					space.read_mem<std::uint64_t>(context + offsetof(_CONTEXT, Rip)));
			}

			put32(3840, static_cast<std::uint32_t>(win::status_breakpoint));
			put32(3844, 1);
			put32(3992, 4);
			put64(4000, dump_buffer_size);
			put32(4152, 0x82);
			put32(4176, 24);

			// Straight out of the shared page, so the dump says the same as everything else.
			const auto shared = st->kuser_shared_data.address();
			space.read_mem(shared + 0x14, buf + 4008, 4);
			space.read_mem(shared + 0x18, buf + 4012, 4);
			space.read_mem(shared + 0x08, buf + 4144, 4);
			space.read_mem(shared + 0x0C, buf + 4148, 4);

			put32(8196, dump_buffer_size);
			put32(8200, dump_buffer_size - 4);
			put32(8204, dump_context_off);
			put32(8208, 3840);

			put32(dump_buffer_size - 4, dump_end_signature);

			space.write_mem(buffer, buf, dump.size());

			THREAD_LOG_INFO("KeCapturePersistentThreadState: wrote 0x{:X} bytes to 0x{:X}",
				dump_buffer_size, buffer);

			return dump_buffer_size;
		});

	state.redirect_ntzw(mod, "TraceEvent",
		[](vcpu&, const std::uint64_t trace_handle, const std::uint32_t flags,
			const std::uint32_t field_size, const addr_t fields) -> NTSTATUS
		{
			THREAD_LOG_INFO("NtTraceEvent(handle=0x{:X}, flags=0x{:X}, fields=0x{:X}/{}): "
				"nothing consumes a trace, so the event is dropped",
				trace_handle, flags, fields, field_size);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "TraceControl",
		[](vcpu&, const std::uint32_t function_code, const addr_t in_buffer,
			const std::uint32_t in_length, const addr_t out_buffer,
			const std::uint32_t out_length, emu_object<std::uint32_t> return_length) -> NTSTATUS
		{
			if (return_length)
				return_length.write(0);

			THREAD_LOG_WARN("NtTraceControl(function={}, in=0x{:X}/{}, out=0x{:X}/{}): there is "
				"no trace session here to control, so nothing was returned",
				function_code, in_buffer, in_length, out_buffer, out_length);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "ManageHotPatch",
		[](vcpu&, const std::uint32_t information_class, const addr_t buffer,
			const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
		{
			if (return_length)
				return_length.write(0);

			THREAD_LOG_WARN("NtManageHotPatch(class={}, buffer=0x{:X}/{}): nothing here is hot "
				"patchable", information_class, buffer, length);

			return STATUS_NOT_SUPPORTED;
		});

	state.redirect_ntzw(mod, "RaiseHardError",
		[](vcpu& cpu, const NTSTATUS error_status, const std::uint32_t parameter_count,
			const std::uint32_t unicode_string_mask, const addr_t parameters,
			const std::uint32_t valid_response_options,
			emu_object<std::uint32_t> response) -> NTSTATUS
		{
			auto& space = *cpu.curr_addr_space();

			THREAD_LOG_ERR("NtRaiseHardError(status=0x{:X}, parameters={}, mask=0x{:X}, "
				"responses=0x{:X})", error_status, parameter_count, unicode_string_mask,
				valid_response_options);

			for (std::uint32_t i = 0; parameters && i < parameter_count && i < 32; ++i)
			{
				const auto value = space.read_mem<addr_t>(parameters + i * sizeof(addr_t));

				if ((unicode_string_mask >> i) & 1)
				{
					const emu_object<_UNICODE_STRING> str(space, value);

					THREAD_LOG_ERR("  parameter[{}] = '{}'", i,
						narrow_wstring(win::read_unicode_string(str)));
				}
				else
				{
					THREAD_LOG_ERR("  parameter[{}] = 0x{:X}", i, value);
				}
			}

			// ResponseNotHandled.
			if (response)
				response.write(1);

			return STATUS_SUCCESS;
		});

	state.redirect_ntzw(mod, "ApphelpCacheControl",
		[](vcpu&, const std::uint32_t service_class, const addr_t data) -> NTSTATUS
		{
			THREAD_LOG_WARN("NtApphelpCacheControl(class={}, data=0x{:X}): there is no shim "
				"cache here", service_class, data);

			return STATUS_SUCCESS;
		});

	// The answer real Windows gives for a state name nothing published.
	state.redirect_ntzw(mod, "QueryWnfStateNameInformation",
		[](vcpu&, const addr_t state_name, const std::uint32_t name_information_class,
			const addr_t explicit_scope, const addr_t information_buffer,
			const std::uint32_t information_buffer_size) -> NTSTATUS
		{
			THREAD_LOG_WARN("NtQueryWnfStateNameInformation(name=0x{:X}, class={}, scope=0x{:X}, "
				"buffer=0x{:X}/{}): nothing here publishes a state name",
				state_name, name_information_class, explicit_scope, information_buffer,
				information_buffer_size);

			return STATUS_OBJECT_NAME_NOT_FOUND;
		});

	state.redirect_ntzw(mod, "QueryWnfStateData",
		[](vcpu&, const addr_t state_name, const addr_t type_id,
			const addr_t explicit_scope, emu_object<std::uint32_t> change_stamp,
			const addr_t buffer, emu_object<std::uint32_t> buffer_size) -> NTSTATUS
		{
			if (change_stamp)
				change_stamp.write(0);

			if (buffer_size)
				buffer_size.write(0);

			THREAD_LOG_WARN("NtQueryWnfStateData(name=0x{:X}, type=0x{:X}, scope=0x{:X}, "
				"buffer=0x{:X}): nothing here publishes a state name",
				state_name, type_id, explicit_scope, buffer);

			return STATUS_OBJECT_NAME_NOT_FOUND;
		});

	state.redirect_ntzw(mod, "QuerySecurityAttributesToken",
		[](vcpu&, const std::uint64_t token_handle, const addr_t attributes,
			const std::uint32_t attribute_count, const addr_t buffer,
			const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
		{
			if (return_length)
				return_length.write(0);

			THREAD_LOG_WARN("NtQuerySecurityAttributesToken(handle=0x{:X}, attributes=0x{:X}/{}, "
				"buffer=0x{:X}/{}): nothing here carries a token",
				token_handle, attributes, attribute_count, buffer, length);

			return STATUS_INVALID_HANDLE;
		});

	// No UEFI variable store, as ExGetFirmwareEnvironmentVariable also reports.
	state.redirect_ntzw(mod, "QuerySystemEnvironmentValueEx",
		[](vcpu&, emu_object<_UNICODE_STRING> variable_name, emu_object<void> vendor_guid,
			[[maybe_unused]] const addr_t value, emu_object<std::uint32_t> value_length,
			[[maybe_unused]] emu_object<std::uint32_t> attributes) -> NTSTATUS
		{
			if (value_length)
				value_length.write(0);

			THREAD_LOG_WARN("NtQuerySystemEnvironmentValueEx('{}', guid=0x{:X}): no uefi "
				"firmware to read from",
				narrow_wstring(win::read_unicode_string(variable_name)), vendor_guid.address());

			return STATUS_NOT_IMPLEMENTED;
		});

	state.redirect_ntzw(mod, "QueryLicenseValue",
		[](vcpu&, emu_object<_UNICODE_STRING> value_name, emu_object<std::uint32_t> type,
			[[maybe_unused]] const addr_t data, const std::uint32_t data_size,
			emu_object<std::uint32_t> return_length) -> NTSTATUS
		{
			if (return_length)
				return_length.write(0);

			if (type)
				type.write(0);

			THREAD_LOG_WARN("NtQueryLicenseValue('{}', buffer={} bytes): nothing here holds "
				"licence values",
				narrow_wstring(win::read_unicode_string(value_name)), data_size);

			return STATUS_OBJECT_NAME_NOT_FOUND;
		});

	// DbgPrompt raises a debug service trap rather than asking, so the trap is the behaviour.
	// The dispatcher takes no exception parameters, so it looks like any other breakpoint.
	state.redirect(mod, "DbgPrompt",
		[st](vcpu& cpu, const addr_t prompt, const addr_t response,
			const std::uint32_t length) -> std::uint32_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto text = prompt ? guest::read_string(space, prompt) : std::string{};

			THREAD_LOG_WARN("DbgPrompt('{}', response=0x{:X}, length={})",
				text, response, length);

			auto* emulator = st->emulator();

			if (emulator && emulator->handle_exception(cpu, cpu_exception::breakpoint))
			{
				THREAD_LOG_WARN("DbgPrompt: the breakpoint was handled, so the call does not return");
				return 0;
			}

			THREAD_LOG_WARN("DbgPrompt: nothing handled the breakpoint -> 0 bytes");

			return 0;
		});
}
