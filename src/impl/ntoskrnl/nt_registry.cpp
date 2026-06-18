#include "nt_helpers.hpp"
#include "../../registry/registry.hpp"

constexpr std::uint32_t status_success              = 0x00000000;
constexpr std::uint32_t status_buffer_overflow      = 0x80000005;
constexpr std::uint32_t status_no_more_entries      = 0x8000001A;
constexpr std::uint32_t status_buffer_too_small     = 0xC0000023;
constexpr std::uint32_t status_object_name_not_found = 0xC0000034;
constexpr std::uint32_t status_invalid_parameter    = 0xC000000D;

constexpr std::uint32_t key_value_basic_information   = 0;
constexpr std::uint32_t key_value_full_information    = 1;
constexpr std::uint32_t key_value_partial_information = 2;

constexpr std::uint32_t key_basic_information = 0;
constexpr std::uint32_t key_full_information  = 2;

constexpr std::size_t registry_key_body_size = 8;

constexpr std::uint32_t reg_created_new_key    = 1;
constexpr std::uint32_t reg_opened_existing_key = 2;

constexpr std::uint32_t rtl_registry_absolute        = 0;
constexpr std::uint32_t rtl_registry_services        = 1;
constexpr std::uint32_t rtl_registry_control         = 2;
constexpr std::uint32_t rtl_registry_devicemap       = 4;
constexpr std::uint32_t rtl_registry_handle          = 0x40000000;

constexpr std::uint32_t rtl_query_registry_subkey    = 0x01;
constexpr std::uint32_t rtl_query_registry_topkey    = 0x02;
constexpr std::uint32_t rtl_query_registry_required  = 0x04;
constexpr std::uint32_t rtl_query_registry_novalue   = 0x08;
constexpr std::uint32_t rtl_query_registry_noexpand  = 0x10;
constexpr std::uint32_t rtl_query_registry_direct    = 0x20;
constexpr std::uint32_t rtl_query_registry_delete    = 0x40;

constexpr std::uint32_t status_object_type_mismatch  = 0xC0000024;

struct guest_rtl_query_registry_table
{
	std::uint64_t query_routine;
	std::uint32_t flags;
	std::uint32_t pad0;
	std::uint64_t name;
	std::uint64_t entry_context;
	std::uint32_t default_type;
	std::uint32_t pad1;
	std::uint64_t default_data;
	std::uint32_t default_length;
	std::uint32_t pad2;
};

static std::wstring read_guest_unicode_string(const emulator_t& emulator, const emulator_t::address_type address)
{
	UNICODE_STRING unicode_string{};
	static_cast<void>(emulator.read_virtual_memory(address, &unicode_string, sizeof(unicode_string)));

	const auto buffer_address = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

	if (!buffer_address || !unicode_string.Length)
	{
		return {};
	}

	const auto char_count = unicode_string.Length / sizeof(wchar_t);
	std::wstring result(char_count, L'\0');
	static_cast<void>(emulator.read_virtual_memory(buffer_address, result.data(), unicode_string.Length));

	return result;
}

static std::string resolve_registry_path(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type object_attributes_address)
{
	if (!object_attributes_address)
	{
		return {};
	}

	OBJECT_ATTRIBUTES oa{};
	static_cast<void>(emulator->read_virtual_memory(object_attributes_address, &oa, sizeof(oa)));

	std::wstring name;
	const auto object_name_address = reinterpret_cast<emulator_t::address_type>(oa.ObjectName);

	if (object_name_address)
	{
		name = read_guest_unicode_string(*emulator, object_name_address);
	}

	const auto root_handle = reinterpret_cast<std::uint64_t>(oa.RootDirectory);

	if (root_handle)
	{
		const auto parent = kernel::active_handle_table().get_object_from_handle<registry_key_object_t>(root_handle);

		if (parent)
		{
			auto child_path = registry_t::normalize_path(name);

			if (child_path.empty())
			{
				return parent->path;
			}

			return parent->path + "/" + child_path;
		}
	}

	return registry_t::normalize_path(name);
}

static std::string resolve_rtl_registry_path(const std::shared_ptr<emulator_t>& emulator,
	const std::uint32_t relative_to, const emulator_t::address_type path_address)
{
	auto path_wide = kernel::read_guest_wstring(*emulator, path_address);
	auto path = registry_t::normalize_path(path_wide);

	switch (relative_to & 0x7FFFFFFF) // mask off RTL_REGISTRY_OPTIONAL flag
	{
		case rtl_registry_absolute:
			return path;
		case rtl_registry_services:
			return "system/currentcontrolset/services/" + path;
		case rtl_registry_control:
			return "system/currentcontrolset/control/" + path;
		case rtl_registry_devicemap:
			return "hardware/devicemap/" + path;
		default:
			return path;
	}
}

static void create_key_handle(const std::shared_ptr<emulator_t>& emulator,
	const std::shared_ptr<registry_key_t>& key, const std::string& path,
	const emulator_t::address_type handle_out, const std::uint32_t desired_access,
	const std::string_view caller_name)
{
	auto key_object = std::make_shared<registry_key_object_t>();
	key_object->key = key;
	key_object->path = path;

	std::array<std::uint8_t, registry_key_body_size> body{};
	const auto body_address = kernel::object_manager->create_object(0, body.data(), body.size(), key_object);
	const auto handle_value = kernel::active_handle_table().create_handle(body_address, desired_access);

	emulator_err_t error = emulator->write_virtual_memory(handle_out, &handle_value, sizeof(handle_value));
	error.throw_if(std::format("{}: write handle", caller_name));

	THREAD_LOG("{}: success (path='{}', handle=0x{:X})", caller_name, path, handle_value);
}

static void write_value_info_response(const std::shared_ptr<emulator_t>& emulator,
	const std::uint32_t info_class, const emulator_t::address_type info_buffer,
	const std::uint32_t length, const emulator_t::address_type result_length_address,
	const std::wstring& value_name_wide, const registry_value_t& value,
	const std::string_view caller_name)
{
	const auto type = static_cast<std::uint32_t>(value.type);
	const auto data_byte_length = static_cast<std::uint32_t>(value.data.size());
	const auto name_byte_length = static_cast<std::uint32_t>(value_name_wide.size() * sizeof(wchar_t));
	constexpr std::uint32_t zero = 0;

	std::vector<std::uint8_t> response;
	std::uint32_t required_size = 0;

	if (info_class == key_value_full_information)
	{
		constexpr std::uint32_t header_size = 20;
		const std::uint32_t data_offset = header_size + name_byte_length;
		required_size = data_offset + data_byte_length;

		response.resize(required_size, 0);
		auto* p = response.data();

		std::memcpy(p + 0x00, &zero, 4);              // TitleIndex
		std::memcpy(p + 0x04, &type, 4);              // Type
		std::memcpy(p + 0x08, &data_offset, 4);       // DataOffset
		std::memcpy(p + 0x0C, &data_byte_length, 4);  // DataLength
		std::memcpy(p + 0x10, &name_byte_length, 4);  // NameLength
		std::memcpy(p + 0x14, value_name_wide.data(), name_byte_length);
		std::memcpy(p + data_offset, value.data.data(), data_byte_length);
	}
	else if (info_class == key_value_partial_information)
	{
		constexpr std::uint32_t header_size = 12;
		required_size = header_size + data_byte_length;

		response.resize(required_size, 0);
		auto* p = response.data();

		std::memcpy(p + 0x00, &zero, 4);              // TitleIndex
		std::memcpy(p + 0x04, &type, 4);              // Type
		std::memcpy(p + 0x08, &data_byte_length, 4);  // DataLength
		std::memcpy(p + 0x0C, value.data.data(), data_byte_length);
	}
	else if (info_class == key_value_basic_information)
	{
		constexpr std::uint32_t header_size = 12;
		required_size = header_size + name_byte_length;

		response.resize(required_size, 0);
		auto* p = response.data();

		std::memcpy(p + 0x00, &zero, 4);              // TitleIndex
		std::memcpy(p + 0x04, &type, 4);              // Type
		std::memcpy(p + 0x08, &name_byte_length, 4);  // NameLength
		std::memcpy(p + 0x0C, value_name_wide.data(), name_byte_length);
	}

	if (result_length_address)
	{
		static_cast<void>(emulator->write_virtual_memory(result_length_address, &required_size, sizeof(required_size)));
	}

	if (!info_buffer || length == 0)
	{
		THREAD_LOG("{}: buffer too small (required={})", caller_name, required_size);
		write_nt_status(emulator, status_buffer_too_small);
		return;
	}

	if (length < required_size)
	{
		static_cast<void>(emulator->write_virtual_memory(info_buffer, response.data(), length));
		THREAD_LOG("{}: buffer overflow (provided={}, required={})", caller_name, length, required_size);
		write_nt_status(emulator, status_buffer_overflow);
		return;
	}

	static_cast<void>(emulator->write_virtual_memory(info_buffer, response.data(), required_size));
	THREAD_LOG("{}: success (wrote {} bytes)", caller_name, required_size);
	write_nt_success(emulator);
}

// RtlWriteRegistryValue(ULONG RelativeTo, PCWSTR Path, PCWSTR ValueName, ULONG ValueType, PVOID Data, ULONG DataSize)
static void handle_write_registry_value(const std::shared_ptr<emulator_t>& emulator,
	std::uint32_t relative_to, emulator_t::address_type path_address,
	emulator_t::address_type value_name_address, std::uint32_t type,
	emulator_t::address_type data_address, std::uint32_t data_size)
{
	const auto key_path = resolve_rtl_registry_path(emulator, relative_to, path_address);
	const auto value_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, value_name_address));

	THREAD_LOG("RtlWriteRegistryValue called (path='{}', value='{}', type={}, size={})",
		key_path, value_name, type, data_size);

	auto key = kernel::registry->create_key(key_path);

	std::vector<std::uint8_t> data_buffer(data_size);

	if (data_address && data_size > 0)
	{
		static_cast<void>(emulator->read_virtual_memory(data_address, data_buffer.data(), data_size));
	}

	key->set_value(value_name, static_cast<registry_type>(type), data_buffer.data(), data_size);

	write_nt_success(emulator);
}

// RtlDeleteRegistryValue(ULONG RelativeTo, PCWSTR Path, PCWSTR ValueName)
static void handle_delete_registry_value(const std::shared_ptr<emulator_t>& emulator,
	std::uint32_t relative_to, emulator_t::address_type path_address,
	emulator_t::address_type value_name_address)
{
	const auto key_path = resolve_rtl_registry_path(emulator, relative_to, path_address);
	const auto value_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, value_name_address));

	THREAD_LOG("RtlDeleteRegistryValue called (path='{}', value='{}')", key_path, value_name);

	auto key = kernel::registry->open_key(key_path);

	if (key)
	{
		key->delete_value(value_name);
	}

	write_nt_success(emulator);
}

// NtOpenKey/ZwOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
static void handle_open_key(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes_address)
{
	const auto path = resolve_registry_path(emulator, object_attributes_address);

	THREAD_LOG("NtOpenKey called (handle_out=0x{:X}, access=0x{:X}, path='{}')",
		handle_out, desired_access, path);

	auto key = kernel::registry->open_key(path);

	if (!key)
	{
		THREAD_LOG("NtOpenKey: key not found '{}'", path);
		write_nt_status(emulator, status_object_name_not_found);
		return;
	}

	create_key_handle(emulator, key, path, handle_out, desired_access, "NtOpenKey");
	write_nt_success(emulator);
}

// NtCreateKey/ZwCreateKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition)
static void handle_create_key(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle_out, std::uint32_t desired_access,
	emulator_t::address_type object_attributes_address, [[maybe_unused]] std::uint32_t title_index,
	[[maybe_unused]] emulator_t::address_type class_string, emulator_t::address_type disposition_address)
{
	const auto path = resolve_registry_path(emulator, object_attributes_address);

	THREAD_LOG("NtCreateKey called (handle_out=0x{:X}, access=0x{:X}, path='{}')",
		handle_out, desired_access, path);

	const bool existed = kernel::registry->key_exists(path);
	auto key = kernel::registry->create_key(path);

	if (disposition_address)
	{
		const std::uint32_t disposition = existed ? reg_opened_existing_key : reg_created_new_key;
		static_cast<void>(emulator->write_virtual_memory(disposition_address, &disposition, sizeof(disposition)));
	}

	create_key_handle(emulator, key, path, handle_out, desired_access, "NtCreateKey");
	write_nt_success(emulator);
}

// NtDeleteKey/ZwDeleteKey(HANDLE KeyHandle)
static void handle_delete_key(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t key_handle)
{
	THREAD_LOG("NtDeleteKey called (handle=0x{:X})", key_handle);

	const auto key_object = kernel::active_handle_table().get_object_from_handle<registry_key_object_t>(key_handle);

	if (!key_object)
	{
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	static_cast<void>(kernel::registry->delete_key(key_object->path));
	write_nt_success(emulator);
}

// ZwFlushKey(HANDLE KeyHandle)
static void handle_flush_key(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t key_handle)
{
	THREAD_LOG("ZwFlushKey called (handle=0x{:X})", key_handle);

	write_nt_success(emulator);
}

// NtQueryValueKey/ZwQueryValueKey(HANDLE, PUNICODE_STRING, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG)
static void handle_query_value_key(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t key_handle, emulator_t::address_type value_name_address,
	std::uint32_t info_class, emulator_t::address_type info_buffer,
	std::uint32_t length, emulator_t::address_type result_length_address)
{
	auto value_name_wide = read_guest_unicode_string(*emulator, value_name_address);
	const auto value_name_narrow = util::narrow_wstring(value_name_wide);

	THREAD_LOG("NtQueryValueKey called (handle=0x{:X}, value='{}', class={}, buffer=0x{:X}, length={})",
		key_handle, value_name_narrow, info_class, info_buffer, length);

	const auto key_object = kernel::active_handle_table().get_object_from_handle<registry_key_object_t>(key_handle);

	if (!key_object || !key_object->key)
	{
		THREAD_WARN_LOG("NtQueryValueKey: invalid handle 0x{:X}", key_handle);
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	const auto* value = key_object->key->query_value(value_name_narrow);

	if (!value)
	{
		THREAD_LOG("NtQueryValueKey: value '{}' not found in '{}'", value_name_narrow, key_object->path);

		if (result_length_address)
		{
			const std::uint32_t zero = 0;
			static_cast<void>(emulator->write_virtual_memory(result_length_address, &zero, sizeof(zero)));
		}

		write_nt_status(emulator, status_object_name_not_found);
		return;
	}

	write_value_info_response(emulator, info_class, info_buffer, length,
		result_length_address, value_name_wide, *value, "NtQueryValueKey");
}

// NtSetValueKey/ZwSetValueKey(HANDLE, PUNICODE_STRING, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize)
static void handle_set_value_key(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t key_handle, emulator_t::address_type value_name_address,
	std::uint32_t title_index, std::uint32_t type,
	emulator_t::address_type data_address, std::uint32_t data_size)
{
	auto value_name_wide = read_guest_unicode_string(*emulator, value_name_address);
	const auto value_name_narrow = util::narrow_wstring(value_name_wide);

	THREAD_LOG("NtSetValueKey called (handle=0x{:X}, value='{}', type={}, data_size={})",
		key_handle, value_name_narrow, type, data_size);

	const auto key_object = kernel::active_handle_table().get_object_from_handle<registry_key_object_t>(key_handle);

	if (!key_object || !key_object->key)
	{
		THREAD_WARN_LOG("NtSetValueKey: invalid handle 0x{:X}", key_handle);
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	std::vector<std::uint8_t> data_buffer;

	if (data_address && data_size > 0)
	{
		data_buffer.resize(data_size);
		static_cast<void>(emulator->read_virtual_memory(data_address, data_buffer.data(), data_size));
	}

	key_object->key->set_value(value_name_narrow, static_cast<registry_type>(type),
		data_buffer.data(), data_buffer.size());

	THREAD_LOG("NtSetValueKey: set '{}' on '{}' (type={}, size={})",
		value_name_narrow, key_object->path, type, data_size);

	write_nt_success(emulator);
}

// NtDeleteValueKey/ZwDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName)
static void handle_delete_value_key(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t key_handle, emulator_t::address_type value_name_address)
{
	auto value_name_wide = read_guest_unicode_string(*emulator, value_name_address);
	const auto value_name_narrow = util::narrow_wstring(value_name_wide);

	const auto key_object = kernel::active_handle_table().get_object_from_handle<registry_key_object_t>(key_handle);

	if (!key_object || !key_object->key)
	{
		THREAD_WARN_LOG("NtDeleteValueKey: invalid handle 0x{:X}", key_handle);
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	const bool deleted = key_object->key->delete_value(value_name_narrow);

	THREAD_LOG("NtDeleteValueKey called (handle=0x{:X}, value='{}', path='{}') -> {}",
		key_handle, value_name_narrow, key_object->path,
		deleted ? "deleted" : "not found");

	write_nt_success(emulator);
}

// NtEnumerateKey/ZwEnumerateKey(HANDLE, ULONG Index, KEY_INFORMATION_CLASS, PVOID, ULONG Length, PULONG ResultLength)
static void handle_enumerate_key(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t key_handle, std::uint32_t index,
	std::uint32_t info_class, emulator_t::address_type info_buffer,
	std::uint32_t length, emulator_t::address_type result_length_address)
{
	THREAD_LOG("NtEnumerateKey called (handle=0x{:X}, index={}, class={}, length={})",
		key_handle, index, info_class, length);

	const auto key_object = kernel::active_handle_table().get_object_from_handle<registry_key_object_t>(key_handle);

	if (!key_object)
	{
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	const auto subkeys = kernel::registry->enumerate_subkeys(key_object->path);

	if (index >= subkeys.size())
	{
		THREAD_LOG("NtEnumerateKey: no more entries (index={}, count={})", index, subkeys.size());
		write_nt_status(emulator, status_no_more_entries);
		return;
	}

	const auto& subkey_name = subkeys[index];
	const auto subkey_name_wide = util::widen_string(subkey_name);
	const auto name_byte_length = static_cast<std::uint32_t>(subkey_name_wide.size() * sizeof(wchar_t));

	// KEY_BASIC_INFORMATION: LastWriteTime(8) + TitleIndex(4) + NameLength(4) + Name(variable)
	constexpr std::uint32_t header_size = 16;
	const std::uint32_t required_size = header_size + name_byte_length;

	if (result_length_address)
	{
		static_cast<void>(emulator->write_virtual_memory(result_length_address, &required_size, sizeof(required_size)));
	}

	if (!info_buffer || length < required_size)
	{
		write_nt_status(emulator, length == 0 ? status_buffer_too_small : status_buffer_overflow);
		return;
	}

	std::vector<std::uint8_t> response(required_size, 0);
	auto* p = response.data();

	// LastWriteTime = 0 (8 bytes)
	constexpr std::uint32_t zero = 0;
	std::memcpy(p + 0x08, &zero, 4);                 // TitleIndex
	std::memcpy(p + 0x0C, &name_byte_length, 4);     // NameLength
	std::memcpy(p + 0x10, subkey_name_wide.data(), name_byte_length);

	static_cast<void>(emulator->write_virtual_memory(info_buffer, response.data(), required_size));

	THREAD_LOG("NtEnumerateKey: returned subkey '{}' at index {}", subkey_name, index);
	write_nt_success(emulator);
}

// NtEnumerateValueKey/ZwEnumerateValueKey(HANDLE, ULONG Index, KEY_VALUE_INFORMATION_CLASS, PVOID, ULONG, PULONG)
static void handle_enumerate_value_key(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t key_handle, std::uint32_t index,
	std::uint32_t info_class, emulator_t::address_type info_buffer,
	std::uint32_t length, emulator_t::address_type result_length_address)
{
	THREAD_LOG("NtEnumerateValueKey called (handle=0x{:X}, index={}, class={}, length={})",
		key_handle, index, info_class, length);

	const auto key_object = kernel::active_handle_table().get_object_from_handle<registry_key_object_t>(key_handle);

	if (!key_object || !key_object->key)
	{
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	const auto value_names = key_object->key->enumerate_values();

	if (index >= value_names.size())
	{
		THREAD_LOG("NtEnumerateValueKey: no more entries (index={}, count={})", index, value_names.size());
		write_nt_status(emulator, status_no_more_entries);
		return;
	}

	const auto& value_name = value_names[index];
	const auto value_name_wide = util::widen_string(value_name);
	const auto* value = key_object->key->query_value(value_name);

	if (!value)
	{
		write_nt_status(emulator, status_object_name_not_found);
		return;
	}

	write_value_info_response(emulator, info_class, info_buffer, length,
		result_length_address, value_name_wide, *value, "NtEnumerateValueKey");
}

// NtQueryKey/ZwQueryKey(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG Length, PULONG ResultLength)
static void handle_query_key(const std::shared_ptr<emulator_t>& emulator,
	std::uint64_t key_handle, std::uint32_t info_class,
	emulator_t::address_type info_buffer, std::uint32_t length,
	emulator_t::address_type result_length_address)
{
	THREAD_LOG("NtQueryKey called (handle=0x{:X}, class={}, length={})",
		key_handle, info_class, length);

	const auto key_object = kernel::active_handle_table().get_object_from_handle<registry_key_object_t>(key_handle);

	if (!key_object || !key_object->key)
	{
		write_nt_status(emulator, status_invalid_parameter);
		return;
	}

	// extract last component of path as key name
	const auto& path = key_object->path;
	const auto last_slash = path.rfind('/');
	const auto key_name = (last_slash != std::string::npos) ? path.substr(last_slash + 1) : path;
	const auto key_name_wide = util::widen_string(key_name);
	const auto name_byte_length = static_cast<std::uint32_t>(key_name_wide.size() * sizeof(wchar_t));

	if (info_class == key_basic_information)
	{
		// KEY_BASIC_INFORMATION: LastWriteTime(8) + TitleIndex(4) + NameLength(4) + Name
		constexpr std::uint32_t header_size = 16;
		const std::uint32_t required_size = header_size + name_byte_length;

		if (result_length_address)
		{
			static_cast<void>(emulator->write_virtual_memory(result_length_address, &required_size, sizeof(required_size)));
		}

		if (!info_buffer || length < required_size)
		{
			write_nt_status(emulator, length == 0 ? status_buffer_too_small : status_buffer_overflow);
			return;
		}

		std::vector<std::uint8_t> response(required_size, 0);
		auto* p = response.data();

		constexpr std::uint32_t zero = 0;
		std::memcpy(p + 0x08, &zero, 4);
		std::memcpy(p + 0x0C, &name_byte_length, 4);
		std::memcpy(p + 0x10, key_name_wide.data(), name_byte_length);

		static_cast<void>(emulator->write_virtual_memory(info_buffer, response.data(), required_size));
		write_nt_success(emulator);
	}
	else if (info_class == key_full_information)
	{
		const auto subkeys = kernel::registry->enumerate_subkeys(key_object->path);
		const auto value_names = key_object->key->enumerate_values();

		const auto subkey_count = static_cast<std::uint32_t>(subkeys.size());
		const auto value_count = static_cast<std::uint32_t>(value_names.size());

		// KEY_FULL_INFORMATION (simplified): LastWriteTime(8) + TitleIndex(4) +
		//   ClassOffset(4) + ClassLength(4) + SubKeys(4) + MaxNameLen(4) + MaxClassLen(4) +
		//   Values(4) + MaxValueNameLen(4) + MaxValueDataLen(4) + Class(variable)
		constexpr std::uint32_t header_size = 44;
		const std::uint32_t required_size = header_size;

		if (result_length_address)
		{
			static_cast<void>(emulator->write_virtual_memory(result_length_address, &required_size, sizeof(required_size)));
		}

		if (!info_buffer || length < required_size)
		{
			write_nt_status(emulator, length == 0 ? status_buffer_too_small : status_buffer_overflow);
			return;
		}

		std::vector<std::uint8_t> response(required_size, 0);
		auto* p = response.data();

		constexpr std::uint32_t zero = 0;
		std::memcpy(p + 0x08, &zero, 4);          // TitleIndex
		std::memcpy(p + 0x0C, &zero, 4);          // ClassOffset
		std::memcpy(p + 0x10, &zero, 4);          // ClassLength
		std::memcpy(p + 0x14, &subkey_count, 4);  // SubKeys
		std::memcpy(p + 0x18, &zero, 4);          // MaxNameLen
		std::memcpy(p + 0x1C, &zero, 4);          // MaxClassLen
		std::memcpy(p + 0x20, &value_count, 4);   // Values
		std::memcpy(p + 0x24, &zero, 4);          // MaxValueNameLen
		std::memcpy(p + 0x28, &zero, 4);          // MaxValueDataLen

		static_cast<void>(emulator->write_virtual_memory(info_buffer, response.data(), required_size));
		write_nt_success(emulator);
	}
	else
	{
		THREAD_WARN_LOG("NtQueryKey: unsupported info class {}", info_class);
		write_nt_status(emulator, status_invalid_parameter);
	}
}

// CmRegisterCallbackEx(PEX_CALLBACK_FUNCTION, PUNICODE_STRING Altitude, PVOID Driver, PVOID Context, PLARGE_INTEGER Cookie)
static void handle_cm_register_callback_ex(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type function, emulator_t::address_type altitude_address,
	emulator_t::address_type driver, emulator_t::address_type context,
	emulator_t::address_type cookie_address)
{
	std::string altitude_string;

	if (altitude_address)
	{
		UNICODE_STRING unicode_string = { };
		static_cast<void>(emulator->read_virtual_memory(altitude_address, &unicode_string, sizeof(unicode_string)));

		const auto buffer_address = reinterpret_cast<emulator_t::address_type>(unicode_string.Buffer);

		if (buffer_address && unicode_string.Length)
		{
			altitude_string = util::narrow_wstring(kernel::read_guest_wstring(*emulator, buffer_address));
		}
	}

	THREAD_LOG("CmRegisterCallbackEx called (function=0x{:X}, altitude='{}', driver=0x{:X}, context=0x{:X}, cookie=0x{:X})",
		function, altitude_string, driver, context, cookie_address);

	if (cookie_address)
	{
		constexpr std::uint64_t dummy_cookie = 1;
		static_cast<void>(emulator->write_virtual_memory(cookie_address, &dummy_cookie, sizeof(dummy_cookie)));
	}

	write_nt_success(emulator);
}

// CmUnRegisterCallback(LARGE_INTEGER Cookie)
static void handle_cm_unregister_callback(const std::shared_ptr<emulator_t>& emulator,
	std::int64_t cookie)
{
	THREAD_LOG("CmUnRegisterCallback called (cookie=0x{:X})", cookie);

	write_nt_success(emulator);
}

// RtlQueryRegistryValues(ULONG RelativeTo, PCWSTR Path, PRTL_QUERY_REGISTRY_TABLE QueryTable, PVOID Context)
static void handle_query_registry_values(const std::shared_ptr<emulator_t>& emulator,
	std::uint32_t relative_to, emulator_t::address_type path_address,
	emulator_t::address_type table_address, [[maybe_unused]] emulator_t::address_type context)
{
	std::string base_path;

	if (relative_to & rtl_registry_handle)
	{
		const auto handle = path_address;
		const auto key_obj = kernel::active_handle_table().get_object_from_handle<registry_key_object_t>(handle);

		if (!key_obj)
		{
			THREAD_WARN_LOG("RtlQueryRegistryValues: invalid handle 0x{:X}", handle);
			write_nt_status(emulator, status_object_name_not_found);
			return;
		}

		base_path = key_obj->path;
	}
	else
	{
		base_path = resolve_rtl_registry_path(emulator, relative_to, path_address);
	}

	THREAD_LOG("RtlQueryRegistryValues called (relative_to=0x{:X}, path='{}')", relative_to, base_path);

	auto current_path = base_path;
	auto entry_address = table_address;

	while (true)
	{
		guest_rtl_query_registry_table entry{};
		static_cast<void>(emulator->read_virtual_memory(entry_address, &entry, sizeof(entry)));

		if (entry.query_routine == 0 && entry.name == 0)
		{
			break;
		}

		entry_address += sizeof(entry);

		if (entry.flags & rtl_query_registry_topkey)
		{
			current_path = base_path;
		}

		if (entry.flags & rtl_query_registry_subkey)
		{
			if (entry.name)
			{
				const auto subkey_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, entry.name));
				current_path = base_path + "/" + registry_t::normalize_path(util::widen_string(subkey_name));
			}

			continue;
		}

		if (entry.flags & rtl_query_registry_novalue)
		{
			continue;
		}

		auto key = kernel::registry->open_key(current_path);

		if (!key)
		{
			if (entry.flags & rtl_query_registry_required)
			{
				THREAD_WARN_LOG("RtlQueryRegistryValues: required key not found (path='{}')", current_path);
				write_nt_status(emulator, status_object_name_not_found);
				return;
			}

			continue;
		}

		std::string value_name;

		if (entry.name)
		{
			value_name = util::narrow_wstring(kernel::read_guest_wstring(*emulator, entry.name));
		}

		const auto* value = key->query_value(value_name);

		const void* data_ptr = nullptr;
		std::uint32_t data_size = 0;
		std::uint32_t data_type = 0;

		std::vector<std::uint8_t> default_data_buf;

		if (value)
		{
			data_ptr = value->data.data();
			data_size = static_cast<std::uint32_t>(value->data.size());
			data_type = static_cast<std::uint32_t>(value->type);
		}
		else if (static_cast<registry_type>(entry.default_type & 0xFF) != registry_type::none
			&& entry.default_data && entry.default_length > 0)
		{
			default_data_buf.resize(entry.default_length);
			static_cast<void>(emulator->read_virtual_memory(
				entry.default_data, default_data_buf.data(), entry.default_length));

			data_ptr = default_data_buf.data();
			data_size = entry.default_length;
			data_type = entry.default_type & 0xFF;
		}
		else if (entry.flags & rtl_query_registry_required)
		{
			THREAD_WARN_LOG("RtlQueryRegistryValues: required value '{}' not found in '{}'",
				value_name, current_path);
			write_nt_status(emulator, status_object_name_not_found);
			return;
		}
		else
		{
			continue;
		}

		if (entry.flags & rtl_query_registry_direct)
		{
			if (!entry.entry_context)
			{
				write_nt_status(emulator, status_invalid_parameter);
				return;
			}

			const bool is_string = data_type == static_cast<std::uint32_t>(registry_type::sz)
				|| data_type == static_cast<std::uint32_t>(registry_type::expand_sz)
				|| data_type == static_cast<std::uint32_t>(registry_type::multi_sz);

			if (is_string)
			{
				UNICODE_STRING ustr{};
				static_cast<void>(emulator->read_virtual_memory(
					entry.entry_context, &ustr, sizeof(ustr)));

				const auto buffer_address = reinterpret_cast<emulator_t::address_type>(ustr.Buffer);

				if (buffer_address && ustr.MaximumLength >= data_size)
				{
					static_cast<void>(emulator->write_virtual_memory(buffer_address, data_ptr, data_size));

					ustr.Length = static_cast<USHORT>(data_size > 2 ? data_size - 2 : 0);
					static_cast<void>(emulator->write_virtual_memory(
						entry.entry_context, &ustr, sizeof(ustr)));
				}
				else if (!buffer_address)
				{
					const auto alloc = emulator->heap_allocate(data_size, prot_read_write);
					const auto alloc_address = alloc.value_or(0);

					if (alloc_address)
					{
						static_cast<void>(emulator->write_virtual_memory(alloc_address, data_ptr, data_size));

						ustr.Length = static_cast<USHORT>(data_size > 2 ? data_size - 2 : 0);
						ustr.MaximumLength = static_cast<USHORT>(data_size);
						ustr.Buffer = reinterpret_cast<PWSTR>(alloc_address);

						static_cast<void>(emulator->write_virtual_memory(
							entry.entry_context, &ustr, sizeof(ustr)));
					}
				}
			}
			else if (data_size <= sizeof(std::uint32_t))
			{
				static_cast<void>(emulator->write_virtual_memory(
					entry.entry_context, data_ptr, data_size));
			}
			else
			{
				std::int32_t size_indicator = 0;
				static_cast<void>(emulator->read_virtual_memory(
					entry.entry_context, &size_indicator, sizeof(size_indicator)));

				if (size_indicator < 0)
				{
					const auto buf_size = static_cast<std::uint32_t>(-size_indicator);

					if (buf_size >= data_size)
					{
						static_cast<void>(emulator->write_virtual_memory(
							entry.entry_context, data_ptr, data_size));
					}
				}
				else
				{
					const auto buf_size = static_cast<std::uint32_t>(size_indicator);

					if (buf_size >= data_size + 2 * sizeof(std::uint32_t))
					{
						static_cast<void>(emulator->write_virtual_memory(
							entry.entry_context, &data_size, sizeof(std::uint32_t)));
						static_cast<void>(emulator->write_virtual_memory(
							entry.entry_context + sizeof(std::uint32_t), &data_type, sizeof(std::uint32_t)));
						static_cast<void>(emulator->write_virtual_memory(
							entry.entry_context + 2 * sizeof(std::uint32_t), data_ptr, data_size));
					}
				}
			}

			THREAD_LOG("RtlQueryRegistryValues: DIRECT read '{}' from '{}' (type={}, size={})",
				value_name, current_path, data_type, data_size);
		}
		else
		{
			THREAD_WARN_LOG("RtlQueryRegistryValues: QueryRoutine mode not implemented for '{}'", value_name);
		}

		if (entry.flags & rtl_query_registry_delete)
		{
			key->delete_value(value_name);
		}
	}

	write_nt_success(emulator);
}

void redirect_ntoskrnl_registry_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_write_registry_value>(emulator, mapped_image, "RtlWriteRegistryValue");
	redirect_handler<handle_delete_registry_value>(emulator, mapped_image, "RtlDeleteRegistryValue");

	redirect_handler<handle_open_key>(emulator, mapped_image, "NtOpenKey");
	redirect_handler<handle_open_key>(emulator, mapped_image, "ZwOpenKey");

	redirect_handler<handle_create_key>(emulator, mapped_image, "NtCreateKey");
	redirect_handler<handle_create_key>(emulator, mapped_image, "ZwCreateKey");

	redirect_handler<handle_delete_key>(emulator, mapped_image, "NtDeleteKey");
	redirect_handler<handle_delete_key>(emulator, mapped_image, "ZwDeleteKey");

	redirect_handler<handle_flush_key>(emulator, mapped_image, "ZwFlushKey");

	redirect_handler<handle_query_value_key>(emulator, mapped_image, "NtQueryValueKey");
	redirect_handler<handle_query_value_key>(emulator, mapped_image, "ZwQueryValueKey");

	redirect_handler<handle_set_value_key>(emulator, mapped_image, "NtSetValueKey");
	redirect_handler<handle_set_value_key>(emulator, mapped_image, "ZwSetValueKey");

	redirect_handler<handle_delete_value_key>(emulator, mapped_image, "NtDeleteValueKey");
	redirect_handler<handle_delete_value_key>(emulator, mapped_image, "ZwDeleteValueKey");

	redirect_handler<handle_enumerate_key>(emulator, mapped_image, "NtEnumerateKey");
	redirect_handler<handle_enumerate_key>(emulator, mapped_image, "ZwEnumerateKey");

	redirect_handler<handle_enumerate_value_key>(emulator, mapped_image, "NtEnumerateValueKey");
	redirect_handler<handle_enumerate_value_key>(emulator, mapped_image, "ZwEnumerateValueKey");

	redirect_handler<handle_query_key>(emulator, mapped_image, "NtQueryKey");
	redirect_handler<handle_query_key>(emulator, mapped_image, "ZwQueryKey");

	redirect_handler<handle_cm_register_callback_ex>(emulator, mapped_image, "CmRegisterCallbackEx");
	redirect_handler<handle_cm_unregister_callback>(emulator, mapped_image, "CmUnRegisterCallback");
	redirect_handler<handle_query_registry_values>(emulator, mapped_image, "RtlQueryRegistryValues");
}
