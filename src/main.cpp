#include "emulator/backend/hypermulator_backend.hpp"
#include "emulator/backend/unicorn_backend.hpp"
#include "emulator/object.hpp"

#include <portable_executable/image.hpp>
#include <portable_executable/file.hpp>
#include <ia32-doc/ia32.hpp>
#include <spdlog/spdlog.h>

#include "kernel_def.hpp"
#include "disassembler/disassembler.hpp"

class mapped_image_t
{
public:
	using string_type = std::string;
	using address_type = emulator_t::address_type;
	using size_type = emulator_t::size_type;
	using export_list_type = std::unordered_map<string_type, address_type>;

	mapped_image_t(string_type name, const address_type base_address, const address_type entry_point, std::vector<std::uint8_t> buffer)
			:	name_(std::move(name)),
				base_address_(base_address),
				entry_point_(entry_point),
				buffer_(std::move(buffer)) { }

	[[nodiscard]] std::optional<address_type> find_export(const string_type& export_name)
	{
		const auto it = exports_.find(export_name);

		if (it != std::ranges::end(exports_))
		{
			return it->second;
		}

		return std::nullopt;
	}

	void register_export(const string_type& export_name, const address_type address)
	{
		exports_[export_name] = address;
	}

	[[nodiscard]] const string_type& name() const
	{
		return name_;
	}

	[[nodiscard]] address_type base_address() const
	{
		return base_address_;
	}

	[[nodiscard]] address_type entry_point() const
	{
		return entry_point_;
	}

	[[nodiscard]] size_type size() const
	{
		return buffer_.size();
	}

	[[nodiscard]] std::span<std::uint8_t> buffer()
	{
		return buffer_;
	}

	[[nodiscard]] std::span<const std::uint8_t> buffer() const
	{
		return buffer_;
	}

	[[nodiscard]] emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& table_entry()
	{
		return table_entry_;
	}

	[[nodiscard]] const emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& table_entry() const
	{
		return table_entry_;
	}

	void set_table_entry(emulator_object_t<_KLDR_DATA_TABLE_ENTRY> object)
	{
		table_entry_ = std::move(object);
	}

protected:
	string_type name_;

	address_type base_address_;
	address_type entry_point_;

	std::vector<std::uint8_t> buffer_;
	export_list_type exports_;

	emulator_object_t<_KLDR_DATA_TABLE_ENTRY> table_entry_;
};

namespace kernel
{
	static emulator_object_t<_KUSER_SHARED_DATA> user_shared_data;

	static emulator_object_t<_KPCR> kpcr;
	static emulator_object_t<_KPRCB> kprcb;

	static emulator_object_t<_LIST_ENTRY> ps_loaded_module_list;
	static std::vector<std::shared_ptr<mapped_image_t>> module_entries;

	static std::shared_ptr<mapped_image_t> emulated_module;

	using function_implementation_t = std::function<void()>;

	static std::unordered_map<emulator_t::address_type, function_implementation_t> redirected_functions;

	[[nodiscard]] std::shared_ptr<mapped_image_t> find_module(const std::string_view name)
	{
		const auto it = std::ranges::find(module_entries, name, &mapped_image_t::name);

		return it != std::ranges::end(module_entries) ? *it : nullptr;
	}

	[[nodiscard]] std::optional<function_implementation_t> find_redirected_function(const emulator_t::address_type address)
	{
		const auto it = redirected_functions.find(address);
		
		if (it != std::ranges::end(redirected_functions))
		{
			return it->second;
		}

		return std::nullopt;
	}
}

template <class T>
static emulator_t::address_type allocate_basic_string(emulator_t& emulator, const std::basic_string_view<T> str,
                                                      const bool terminate)
{
	if (str.empty())
	{
		throw std::runtime_error("unable to allocate empty string");
	}

	const std::span<const std::uint8_t> buffer = {
		reinterpret_cast<const std::uint8_t*>(str.data()),
		str.size() * sizeof(T)
	};

	const std::size_t buffer_size = buffer.size() + (terminate ? sizeof(T) : 0);

	const auto allocation = emulator.heap_allocate(buffer_size, prot_read_write);

	emulator_err_t error = allocation.error_or({});

	error.throw_if("string heap allocation");

	error = emulator.write_virtual_memory(*allocation, buffer);

	error.throw_if("write memory");

	if (terminate)
	{
		constexpr T terminator = { };

		error = emulator.write_virtual_memory(*allocation + buffer.size(), &terminator, sizeof(terminator));

		error.throw_if("write memory");
	}

	error = emulator.hook_memory(
		[&emulator](const emulator_t::address_type accessed_address, const protection_t access) -> bool
		{
			const auto rip = emulator.read_register<x86::reg::rip, emulator_t::address_type>();

			spdlog::info("instruction at 0x{:X} accessed allocated string (string address=0x{:X})", rip, accessed_address);

			return false;
		},
		prot_read_write,
		*allocation,
		*allocation + buffer_size
	).error_or({});

	error.throw_if("object hook attach");

	return *allocation;
}

static emulator_t::address_type allocate_string(emulator_t& emulator, const std::string_view str,
	                                            const bool terminate)
{
	return allocate_basic_string(emulator, str, terminate);
}

static emulator_t::address_type allocate_wstring(emulator_t& emulator, const std::wstring_view str,
                                                 const bool terminate)
{
	return allocate_basic_string(emulator, str, terminate);
}

static UNICODE_STRING init_unicode_string(emulator_t& emulator, const std::wstring_view str)
{
	const emulator_t::address_type buffer = allocate_wstring(emulator, str, true);

	const std::uint16_t length = static_cast<std::uint16_t>(str.size() * sizeof(wchar_t));
	const std::uint16_t max_length = length + sizeof(wchar_t);

	const UNICODE_STRING result = {
		.Length = length,
		.MaximumLength = max_length,
		.Buffer = reinterpret_cast<PWSTR>(buffer)
	};

	return result;
}

static emulator_object_t<UNICODE_STRING> allocate_unicode_string_object(const std::shared_ptr<emulator_t>& emulator,
	const std::wstring_view str,
	const std::string& object_name = {})
{
	const UNICODE_STRING contents = init_unicode_string(*emulator, str);

	return emulator_object_t<UNICODE_STRING>::allocate(emulator, contents, object_name);
}

static void relocate_image(portable_executable::image_t* const image, const emulator_t::address_type runtime_base_address)
{
	const auto nt_headers = image->nt_headers();
	const emulator_t::address_type delta = runtime_base_address - nt_headers->optional_header.image_base;

	for (const auto [descriptor, virtual_address] : image->relocations())
	{
		if (descriptor.type == portable_executable::relocation_type_t::dir64)
		{
			const auto patch = reinterpret_cast<std::uint64_t*>(image->as<std::uint64_t>() + virtual_address + descriptor.offset);

			*patch += delta;
		}
	}
}

static void fix_image_imports(portable_executable::image_t* const image)
{
	for (const auto current_import : image->imports())
	{
		const auto import_module = kernel::find_module(current_import.module_name);

		if (!import_module)
		{
			throw std::runtime_error("unable to find import module");
		}

		const auto module_export = import_module->find_export(current_import.import_name);

		if (!module_export)
		{
			throw std::runtime_error("unable to find export in module");
		}

		current_import.address = reinterpret_cast<std::uint8_t*>(*module_export);
	}
}

static PLIST_ENTRY get_module_list_entry_address(const emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& object)
{
	return reinterpret_cast<PLIST_ENTRY>(object.address()) + offsetof(_KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
}

static void set_module_list_entry_flink(emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& object, const PLIST_ENTRY flink)
{
	auto current = object.read();

	current.InLoadOrderLinks.Flink = flink;

	object.write(current);
}

static void set_module_list_entry_blink(emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& object, const PLIST_ENTRY blink)
{
	auto current = object.read();

	current.InLoadOrderLinks.Blink = blink;

	object.write(current);
}

static void set_module_list_entry_flink(emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& object, const emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& flink)
{
	const auto list_entry = get_module_list_entry_address(flink);

	set_module_list_entry_flink(object, list_entry);
}

static void set_module_list_entry_blink(emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& object, const emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& blink)
{
	const auto list_entry = get_module_list_entry_address(blink);

	set_module_list_entry_blink(object, list_entry);
}

static void set_list_entry_flink(emulator_object_t<LIST_ENTRY>& object, const PLIST_ENTRY flink)
{
	auto current = object.read();

	current.Flink = flink;

	object.write(current);
}

static void set_list_entry_blink(emulator_object_t<LIST_ENTRY>& object, const PLIST_ENTRY blink)
{
	auto current = object.read();

	current.Blink = blink;

	object.write(current);
}

static void set_loaded_module_list_flink(const emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& flink)
{
	const auto list_entry = get_module_list_entry_address(flink);

	set_list_entry_flink(kernel::ps_loaded_module_list, list_entry);
}

static void set_loaded_module_list_blink(const emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& blink)
{
	const auto list_entry = get_module_list_entry_address(blink);

	set_list_entry_blink(kernel::ps_loaded_module_list, list_entry);
}

static void collect_module_exports(portable_executable::image_t* const pe_image, mapped_image_t& mapped_image)
{
	const auto local_image_address = pe_image->as<const std::uint8_t*>();

	for (const auto current_export : pe_image->exports())
	{
		const std::uint32_t rva = static_cast<std::uint32_t>(current_export.address - local_image_address);
		const emulator_t::address_type runtime_address = mapped_image.base_address() + rva;

		mapped_image.register_export(current_export.name, runtime_address);
	}
}

static void add_to_loaded_module_list(const std::shared_ptr<emulator_t>& emulator, const std::shared_ptr<mapped_image_t>& mapped_image)
{
	_KLDR_DATA_TABLE_ENTRY contents = { };

	contents.DllBase = reinterpret_cast<void*>(mapped_image->base_address());
	contents.SizeOfImage = static_cast<std::uint32_t>(mapped_image->size());
	contents.EntryPoint = reinterpret_cast<void*>(mapped_image->entry_point());

	contents.BaseDllName = init_unicode_string(*emulator, L"test_bin.sys");
	contents.FullDllName = init_unicode_string(*emulator, L"\\??\\C:\\Program Files\\test_bin.sys");

	const auto module_list = reinterpret_cast<PLIST_ENTRY>(kernel::ps_loaded_module_list.address());

	const std::shared_ptr<mapped_image_t>& last_entry = kernel::module_entries.empty()
		                                                    ? nullptr
		                                                    : kernel::module_entries.back();

	contents.InLoadOrderLinks.Flink = module_list;
	contents.InLoadOrderLinks.Blink = last_entry
		                                  ? get_module_list_entry_address(last_entry->table_entry())
		                                  : module_list;

	auto object = emulator_object_t<_KLDR_DATA_TABLE_ENTRY>::allocate(emulator, contents, mapped_image->name());

	if (last_entry)
	{
		set_module_list_entry_flink(last_entry->table_entry(), object);
	}
	else
	{
		set_loaded_module_list_flink(object);
	}

	set_loaded_module_list_blink(object);

	mapped_image->table_entry() = std::move(object);

	kernel::module_entries.push_back(mapped_image);
}

static void redirect_image_export(const kernel::function_implementation_t& function_impl,
                                  const portable_executable::image_t* const pe_image,
                                  const mapped_image_t& mapped_image, const std::string_view name)
{
	const auto local_export_address = pe_image->find_export(name);

	if (!local_export_address)
	{
		throw std::runtime_error("unable to find export");
	}

	const std::uint32_t rva = static_cast<std::uint32_t>(local_export_address - pe_image->as<const std::uint8_t*>());

	const emulator_t::address_type export_runtime_address = mapped_image.base_address() + rva;

	kernel::redirected_functions[export_runtime_address] = function_impl;
}

static void write_return_value(const std::shared_ptr<emulator_t>& emulator, const std::uint64_t value)
{
	emulator->write_register<x86::reg::rax>(value);
}

static void write_nt_status(const std::shared_ptr<emulator_t>& emulator, const std::uint32_t code)
{
	write_return_value(emulator, code);
}

static void write_nt_success(const std::shared_ptr<emulator_t>& emulator)
{
	write_nt_status(emulator, 0);
}

static void write_dummy_handle(const std::shared_ptr<emulator_t>& emulator, const emulator_t::address_type handle_address)
{
	constexpr std::uint64_t handle_value = 0x1337;

	const emulator_err_t error = emulator->write_virtual_memory(handle_address, &handle_value, sizeof(handle_value));

	error.throw_if("write memory");
}

static void redirect_ntoskrnl_functions(const std::shared_ptr<emulator_t>& emulator, const mapped_image_t& mapped_image,
                                        const portable_executable::image_t* const pe_image)
{
	redirect_image_export(
		[emulator]
		{
			const auto r9 = emulator->read_register<x86::reg::r9, std::uint64_t>();

			spdlog::info("RtlWriteRegistryValue called with type: 0x{:X}", r9);

			write_nt_success(emulator);
		},
		pe_image,
		mapped_image,
		"RtlWriteRegistryValue"
	);

	redirect_image_export(
		[emulator]
		{
			spdlog::info("RtlDeleteRegistryValue called");

			write_nt_success(emulator);
		},
		pe_image,
		mapped_image,
		"RtlDeleteRegistryValue"
	);

	redirect_image_export(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto rdx = emulator->read_register<x86::reg::rdx, std::uint32_t>();

			spdlog::info("ZwOpenKey called (desired access=0x{:X})", rdx);

			write_dummy_handle(emulator, rcx);

			write_nt_success(emulator);
		},
		pe_image,
		mapped_image,
		"ZwOpenKey"
	);

	redirect_image_export(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();

			spdlog::info("ZwFlushKey called (key handle=0x{:X})", rcx);

			write_nt_success(emulator);
		},
		pe_image,
		mapped_image,
		"ZwFlushKey"
	);

	redirect_image_export(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();

			spdlog::info("ZwClose called (handle=0x{:X})", rcx);

			write_nt_success(emulator);
		},
		pe_image,
		mapped_image,
		"ZwClose"
	);

	redirect_image_export(
		[emulator]
		{
			const auto ecx = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();
			const auto r8 = emulator->read_register<x86::reg::r8, std::uint64_t>();

			spdlog::info("RtlDuplicateUnicodeString called (string in=0x{:X})", rdx);

			if ((ecx & 0xFFFFFFFC) != 0 ||
				((ecx & 2) != 0 && (ecx & 1) == 0) ||
				!r8)
			{
				write_nt_status(emulator, 0xC000000D);

				return;
			}

			auto destination_string_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, r8);

			std::uint16_t length = 0;
			std::uint16_t max_length = 0;

			if (rdx)
			{
				const auto source_string_object = emulator_object_t<UNICODE_STRING>::view_at(emulator, rdx);
				const auto source_string = source_string_object.read();

				if ((source_string.Length & 1) != 0 ||
					(source_string.MaximumLength & 1) != 0 ||
					source_string.Length > source_string.MaximumLength ||
					source_string.MaximumLength == 0xFFFF ||
					(!source_string.Buffer && (source_string.Length || source_string.MaximumLength)))
				{
					write_nt_status(emulator, 0xC000000D);

					return;
				}

				length = source_string.Length;
			}

			if (ecx & 1)
			{
				if (length == 0xFFFE)
				{
					write_nt_status(emulator, 0xC0000106);

					return;
				}

				max_length = length + 2;
			}
			else
			{
				max_length = length;
			}

			if ((ecx & 2) == 0 && !length)
			{
				max_length = 0;
			}

			PWSTR guest_buffer = nullptr;

			if (max_length)
			{
				const auto buffer_allocation = emulator->heap_allocate(max_length, prot_read_write);

				emulator_err_t error = buffer_allocation.error_or({});

				error.throw_if("string heap allocation");

				std::vector<std::uint8_t> buffer(max_length);

				error = emulator->read_virtual_memory(*buffer_allocation, buffer);

				error.throw_if("read memory");

				if (ecx & 1)
				{
					*reinterpret_cast<std::uint16_t*>(buffer.data() + length) = 0;
				}

				error = emulator->write_virtual_memory(*buffer_allocation, buffer);

				error.throw_if("write memory");

				guest_buffer = reinterpret_cast<PWSTR>(*buffer_allocation);
			}

			const UNICODE_STRING destination_string = {
				.Length = length,
				.MaximumLength = max_length,
				.Buffer = guest_buffer
			};

			destination_string_object.write(destination_string);

			write_nt_success(emulator);
		},
		pe_image,
		mapped_image,
		"RtlDuplicateUnicodeString"
	);

	redirect_image_export(
		[emulator]
		{
			spdlog::info("ExSystemTimeToLocalTime called");
		},
		pe_image,
		mapped_image,
		"ExSystemTimeToLocalTime"
	);

	redirect_image_export(
		[emulator]
		{
			spdlog::info("RtlTimeToTimeFields called");
		},
		pe_image,
		mapped_image,
		"RtlTimeToTimeFields"
	);

	redirect_image_export(
		[emulator]
		{
			spdlog::info("vswprintf_s called");

			write_return_value(emulator, 0);
		},
		pe_image,
		mapped_image,
		"vswprintf_s"
	);

	redirect_image_export(
		[emulator]
		{
			spdlog::info("swprintf_s called");

			write_return_value(emulator, 0);
		},
		pe_image,
		mapped_image,
		"swprintf_s"
	);

	redirect_image_export(
		[emulator]
		{
			const auto ecx = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();
			const auto r8d = emulator->read_register<x86::reg::r8, std::uint32_t>();

			spdlog::info("ExAllocatePoolWithTag called (type={}, size=0x{:X}, tag={})", ecx, rdx, r8d);

			const auto allocation = emulator->heap_allocate(rdx, prot_read_write, true);

			const emulator_err_t error = allocation.error_or({});

			error.throw_if("pool heap allocation");

			emulator->write_register<x86::reg::rax>(*allocation);
		},
		pe_image,
		mapped_image,
		"ExAllocatePoolWithTag"
	);

	redirect_image_export(
		[emulator]
		{
			const auto rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();
			const auto rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();
	
			spdlog::info("ExFreePoolWithTag called (buffer=0x{:X}, tag={})", rcx, rdx);
		},
		pe_image,
		mapped_image,
		"ExFreePoolWithTag"
	);
}

static std::shared_ptr<mapped_image_t> map_kernel_image(const std::shared_ptr<emulator_t>& emulator,
                                                        const std::string_view name, const bool fix_imports = true)
{
	portable_executable::file_t pe_file(name);

	if (!pe_file.load())
	{
		spdlog::error("unable to load portable executable file");

		return { };
	}

	const auto pe_image = pe_file.image();
	const auto nt_headers = pe_image->nt_headers();

	const auto image_size = nt_headers->optional_header.size_of_image;

	const auto base_address = emulator->heap_allocate(image_size, prot_all, true);

	if (!base_address)
	{
		spdlog::error("unable to map kernel memory");

		return { };
	}

	if (const auto load_config = pe_image->load_config())
	{
		if (const auto security_cookie_absolute = load_config->security_cookie)
		{
			const auto security_cookie_rva = security_cookie_absolute - nt_headers->optional_header.image_base;

			*reinterpret_cast<std::uint64_t*>(pe_image->as<std::uint64_t>() + security_cookie_rva) += *base_address;
		}
	}

	relocate_image(pe_image, *base_address);

	if (fix_imports)
	{
		fix_image_imports(pe_image);
	}

	const auto image_start = pe_image->as<const std::uint8_t*>();
	const std::vector image_buffer(image_start, image_start + nt_headers->optional_header.size_of_image);

	if (const auto error = emulator->write_virtual_memory(*base_address, image_buffer))
	{
		spdlog::error("unable to write kernel memory");

		return { };
	}

	const mapped_image_t::address_type entry_point = *base_address + nt_headers->optional_header.address_of_entry_point;

	auto mapped_image = std::make_shared<mapped_image_t>(std::string(name), *base_address, entry_point, image_buffer);

	add_to_loaded_module_list(emulator, mapped_image);
	collect_module_exports(pe_image, *mapped_image);

	if (name == "ntoskrnl.exe")
	{
		redirect_ntoskrnl_functions(emulator, *mapped_image, pe_image);
	}

	return mapped_image;
}

static void set_up_user_shared_data(const std::shared_ptr<emulator_t>& emulator)
{
	_KUSER_SHARED_DATA contents = { };

	contents.NtBuildNumber = 19045;
	contents.NtMajorVersion = 10;
	contents.NtMinorVersion = 0;

	kernel::user_shared_data = emulator_object_t<_KUSER_SHARED_DATA>::allocate_at(emulator, contents, 0xFFFFF78000000000);
}

static emulator_object_t<_DRIVER_OBJECT> set_up_driver_object(const std::shared_ptr<emulator_t>& emulator, const mapped_image_t& image)
{
	_DRIVER_OBJECT contents = { };

	const auto& table_entry = image.table_entry();

	contents.DriverSection = reinterpret_cast<void*>(table_entry.address());
	contents.DriverStart = reinterpret_cast<void*>(image.base_address());
	contents.DriverSize = static_cast<std::uint32_t>(image.size());

	return emulator_object_t<_DRIVER_OBJECT>::allocate(emulator, contents, image.name());
}

static void set_up_driver_entry(const std::shared_ptr<emulator_t>& emulator)
{
	const auto driver_object = set_up_driver_object(emulator, *kernel::emulated_module);
	const auto registry_path = allocate_unicode_string_object(emulator, L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\testbin", "RegistryPath");

	emulator->write_register<x86::reg::rcx>(driver_object.address());
	emulator->write_register<x86::reg::rdx>(registry_path.address());
}

static void set_up_ps_loaded_module_list(const std::shared_ptr<emulator_t>& emulator)
{
	kernel::ps_loaded_module_list = emulator_object_t<_LIST_ENTRY>::allocate(emulator, "PsLoadedModuleList");
}

static void set_up_stack(emulator_t& emulator)
{
	constexpr emulator_t::size_type stack_size = 0x10000;

	const auto stack_base_address = emulator.heap_allocate(stack_size, prot_read_write);

	emulator_err_t error = stack_base_address.error_or({});

	error.throw_if("map stack");

	const emulator_t::address_type starting_rsp_value = *stack_base_address + stack_size - 0x1000 - 8;

	emulator.write_register<x86::reg::rsp>(starting_rsp_value);

	error = emulator.write_virtual_memory(starting_rsp_value, &emulator_t::thread_return_address, sizeof(emulator_t::thread_return_address));

	error.throw_if("set return address");
}

static void set_up_kprcb(const std::shared_ptr<emulator_t>& emulator)
{
	kernel::kprcb = emulator_object_t<_KPRCB>::allocate(emulator);
}

static void set_up_kpcr(const std::shared_ptr<emulator_t>& emulator)
{
	set_up_kprcb(emulator);

	kernel::kpcr = emulator_object_t<_KPCR>::allocate(emulator);

	_KPCR contents = { };

	contents.Self = reinterpret_cast<_KPCR*>(kernel::kpcr.address());
	contents.CurrentPrcb = reinterpret_cast<_KPRCB*>(kernel::kprcb.address());

	kernel::kpcr.write(contents);
}

static void set_up_kernel_gs(const std::shared_ptr<emulator_t>& emulator)
{
	set_up_kpcr(emulator);

	const emulator_err_t error = emulator->write_gs_base(kernel::kpcr.address());

	error.throw_if("write kernel gs base");

	spdlog::info("mapped kernel gs at 0x{:X}", kernel::kpcr.address());
}

static void set_up_idt(const std::shared_ptr<emulator_t>& emulator, const mapped_image_t& nt_image)
{
	constexpr std::uint32_t handler_count = 256;
	constexpr emulator_t::size_type idt_size = handler_count * sizeof(segment_descriptor_interrupt_gate_64);

	const auto idt_base_address = emulator->heap_allocate(idt_size, prot_read, true);

	emulator_err_t error = idt_base_address.error_or({});

	error.throw_if("map IDT");

	const emulator_t::address_type handler_address = nt_image.base_address() + (nt_image.size() / 2);

	for (std::uint32_t i = 0; i < handler_count; i++)
	{
		const std::uint32_t offset = i * sizeof(segment_descriptor_interrupt_gate_64);

		const std::string name = std::format("IDT vector #{:X}", i);

		auto entry_object = emulator_object_t<segment_descriptor_interrupt_gate_64>::view_at(emulator, *idt_base_address + offset, name);

		segment_descriptor_interrupt_gate_64 contents = { };

		contents.offset_low = handler_address & 0xFFFF;
		contents.offset_middle = (handler_address >> 16) & 0xFFFF;
		contents.offset_high = (handler_address >> 32) & 0xFFFF'FFFF;

		entry_object.write(contents);
	}

	error = emulator->write_idt(*idt_base_address, idt_size - 1);

	error.throw_if("loading IDT");

	spdlog::info("mapped IDT at 0x{:X}", *idt_base_address);
}

std::int32_t main()
{
	constexpr std::string_view pe_file_name = "test.bin";
	constexpr std::string_view nt_file_name = "ntoskrnl.exe";

	try
	{
		const auto emulator = std::static_pointer_cast<emulator_t>(std::make_shared<hypermulator_t>());

		set_up_stack(*emulator);
		set_up_kernel_gs(emulator);
		set_up_ps_loaded_module_list(emulator);
		set_up_user_shared_data(emulator);

		const auto nt_image = map_kernel_image(emulator, nt_file_name, false);
		map_kernel_image(emulator, "HAL.dll", false);
		map_kernel_image(emulator, "cng.sys", false);

		kernel::emulated_module = map_kernel_image(emulator, pe_file_name);

		set_up_idt(emulator, *nt_image);

	    const emulator_t::address_type base_address = kernel::emulated_module->base_address();
		const emulator_t::address_type entry_point_address = kernel::emulated_module->entry_point();

		spdlog::info("mapped ntoskrnl at 0x{:X}", nt_image->base_address());
		spdlog::info("mapped image at 0x{:X}", base_address);

		emulator_err_t error = emulator->hook_basic_block(
			[emulator]()
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
				const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

				emulator_t::address_type return_address = 0;

				const emulator_err_t read_error = emulator->read_virtual_memory(rsp, &return_address, sizeof(return_address));

				read_error.throw_if("read from stack");

				if (const auto redirected_function = kernel::find_redirected_function(rip))
				{
					spdlog::info("redirecting function at 0x{:X} (return address=0x{:X})", rip, return_address);

					(*redirected_function)();

					emulator->write_register<x86::reg::rsp>(rsp + 8);
					emulator->write_register<x86::reg::rip>(return_address);
				}
				else
				{
					spdlog::error("unimplemented function at 0x{:X} (return address=0x{:X})", rip, return_address);

					emulator->write_register<x86::reg::rip, emulator_t::address_type>(-1);
				}
			},
			nt_image->base_address(),
			nt_image->base_address() + nt_image->size()
		).error_or({});
		 
		error.throw_if("basic block hook attach");

		error = emulator->hook_instruction(x86::insn::cpuid,
			[emulator]()
			{
				const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
				const auto rax = emulator->read_register<x86::reg::rax, emulator_t::address_type>();

				spdlog::info("cpuid executed at 0x{:X} (rax=0x{:X})", rip, rax);

				return false;
			},
			emulator_t::default_start_address,
			emulator_t::default_end_address
		).error_or({});

		error.throw_if("instruction hook attach");

		set_up_driver_entry(emulator);

		error = emulator->run_at(entry_point_address, emulator_t::thread_return_address);

		const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

		spdlog::info("emulation finished at rip=0x{:X}", rip);

		error.throw_if("emulation running");
	}
	catch (const std::exception& e)
	{
		spdlog::error(e.what());
	}

	return 0;
}
