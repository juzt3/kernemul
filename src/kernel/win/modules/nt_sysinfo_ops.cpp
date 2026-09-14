#include "nt_sysinfo_ops.hpp"
#include "../win_kernel.hpp"
#include "../objects.hpp"
#include "../filesystem.hpp"
#include "../process_params.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <chrono>
#include <string>
#include <string_view>
#include <cstddef>

namespace
{

// SYSTEM_INFORMATION_CLASS, the two answerable from what the emulator knows
// about itself.
enum system_information_class : std::uint32_t
{
	system_basic_information        = 0,
	system_time_of_day_information  = 3,
	system_numa_processor_map       = 55,

	// Nothing is emulated here, so this is the basic information verbatim.
	system_emulation_basic_information = 62,
};

#pragma pack(push, 4)
struct system_basic_information_t
{
	std::uint32_t reserved;
	std::uint32_t timer_resolution;
	std::uint32_t page_size;
	std::uint32_t number_of_physical_pages;
	std::uint32_t lowest_physical_page_number;
	std::uint32_t highest_physical_page_number;
	std::uint32_t allocation_granularity;
	std::uint64_t minimum_user_mode_address;
	std::uint64_t maximum_user_mode_address;
	std::uint64_t active_processors_affinity_mask;
	std::int8_t   number_of_processors;
};

// GROUP_AFFINITY.
struct group_affinity_t
{
	std::uint64_t mask;
	std::uint16_t group;
	std::uint16_t reserved[3];
};

// SYSTEM_NUMA_INFORMATION, cut to the one node this machine has.
struct system_numa_information_t
{
	std::uint32_t   highest_node_number;
	std::uint32_t   reserved;
	group_affinity_t node[1];
};

struct system_time_of_day_information_t
{
	std::int64_t  boot_time;
	std::int64_t  current_time;
	std::int64_t  time_zone_bias;
	std::uint32_t time_zone_id;
	std::uint32_t reserved;
	std::uint64_t boot_time_bias;
	std::uint64_t sleep_time_bias;
};
#pragma pack(pop)

// The allocation granularity every Windows has had, and the clock tick the
// KeQueryTimeIncrement handler already reports.
constexpr std::uint32_t allocation_granularity = 0x10000;
constexpr std::uint32_t clock_increment_100ns = 156250;

// LANGID 0x0409, en-US: the one the guest is set up as everywhere else.
constexpr std::uint32_t langid_en_us = 0x0409;

// The same pseudo-handle the task handlers use for the process itself.
constexpr std::uint64_t current_process_handle = ~std::uint64_t{0};

}

// What the guest asks the system about itself, and the handle operations that
// are not tied to any one kind of object.
void modules::register_ntoskrnl_sysinfo_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect_ntzw(mod, "QuerySystemTime",
		[](vcpu&, emu_object<std::int64_t> system_time) -> NTSTATUS
		{
			if (!system_time)
				return STATUS_INVALID_PARAMETER;

			const auto now = static_cast<std::int64_t>(win_system_time());
			system_time.write(now);

			THREAD_LOG_INFO("NtQuerySystemTime() -> {}", now);

			return STATUS_SUCCESS;
		});

	// The same steady clock KeQueryPerformanceCounter reads, so the two agree
	// about how much time passed between them.
	state.redirect_ntzw(mod, "QueryPerformanceCounter",
		[](vcpu&, emu_object<std::int64_t> performance_counter,
			emu_object<std::int64_t> performance_frequency) -> NTSTATUS
		{
			if (!performance_counter)
				return STATUS_INVALID_PARAMETER;

			const auto now = std::chrono::steady_clock::now().time_since_epoch();
			const auto ticks = std::chrono::duration_cast<win_ticks>(now).count();

			performance_counter.write(ticks);

			if (performance_frequency)
				performance_frequency.write(win_ticks::period::den);

			THREAD_LOG_INFO("NtQueryPerformanceCounter() -> {}", ticks);

			return STATUS_SUCCESS;
		});

	auto query_system_information = [st](vcpu& cpu, const std::uint32_t system_information_class,
		const addr_t system_information, const std::uint32_t length,
		emu_object<std::uint32_t> return_length) -> NTSTATUS
	{
		auto& space = *cpu.curr_addr_space();

		switch (system_information_class)
		{
		case system_basic_information:
		case system_emulation_basic_information:
		{
			if (return_length)
				return_length.write(sizeof(system_basic_information_t));

			if (length < sizeof(system_basic_information_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			const auto range = space.mmu_->phys_range();
			const auto page = static_cast<std::uint32_t>(space.mmu_->page_size());
			const auto cpus = cpu.emu()->cpus().size();

			system_basic_information_t info{};
			info.timer_resolution = clock_increment_100ns;
			info.page_size = page;
			info.number_of_physical_pages = static_cast<std::uint32_t>(range.second / page);
			info.lowest_physical_page_number = static_cast<std::uint32_t>(range.first / page);
			info.highest_physical_page_number =
				static_cast<std::uint32_t>((range.first + range.second) / page);
			info.allocation_granularity = allocation_granularity;
			info.active_processors_affinity_mask = cpus >= 64
				? ~std::uint64_t{0} : (std::uint64_t{1} << cpus) - 1;
			info.number_of_processors = static_cast<std::int8_t>(cpus);

			emu_object<system_basic_information_t>(space, system_information).write(info);

			THREAD_LOG_INFO("NtQuerySystemInformation(SystemBasicInformation): {} cpu(s), "
				"{} physical page(s)", cpus, info.number_of_physical_pages);

			return STATUS_SUCCESS;
		}

		case system_time_of_day_information:
		{
			if (return_length)
				return_length.write(sizeof(system_time_of_day_information_t));

			if (length < sizeof(system_time_of_day_information_t))
				return STATUS_INFO_LENGTH_MISMATCH;

			const auto now = static_cast<std::int64_t>(win_system_time());

			system_time_of_day_information_t info{};
			info.boot_time = st->boot_time;
			info.current_time = now;

			emu_object<system_time_of_day_information_t>(space, system_information).write(info);

			THREAD_LOG_INFO("NtQuerySystemInformation(SystemTimeOfDayInformation): up {}s",
				win_ticks(now - st->boot_time) / std::chrono::seconds(1));

			return STATUS_SUCCESS;
		}

		// ntdll treats a failure here as fatal. One node, every processor in it.
		case system_numa_processor_map:
		{
			system_numa_information_t info{};
			info.highest_node_number = 0;
			const auto cpus = cpu.emu()->cpus().size();
			info.node[0].mask = cpus >= 64 ? ~0ull : (1ull << cpus) - 1;
			info.node[0].group = 0;

			const auto written = std::min<std::size_t>(length, sizeof(info));

			if (return_length)
				return_length.write(static_cast<std::uint32_t>(written));

			if (written < offsetof(system_numa_information_t, node))
				return STATUS_INFO_LENGTH_MISMATCH;

			cpu.curr_addr_space()->write_mem(system_information, &info, written);

			THREAD_LOG_INFO("NtQuerySystemInformation(SystemNumaProcessorMap): "
				"1 node, processor mask 0x{:X}", info.node[0].mask);

			return STATUS_SUCCESS;
		}

		default:
			THREAD_LOG_WARN("NtQuerySystemInformation: unhandled class {}",
				system_information_class);
			return STATUS_INVALID_INFO_CLASS;
		}
	};

	// The Ex form takes an input buffer naming which processor group or handle
	// the question is about. There is one group and the classes answered here
	// do not take an input, so it is only reported.
	auto query_system_information_ex = [query_system_information](vcpu& cpu,
		const std::uint32_t system_information_class, const addr_t input_buffer,
		const std::uint32_t input_buffer_length, const addr_t system_information,
		const std::uint32_t length, emu_object<std::uint32_t> return_length) -> NTSTATUS
	{
		THREAD_LOG_INFO("NtQuerySystemInformationEx: input=0x{:X}/{}",
			input_buffer, input_buffer_length);

		return query_system_information(cpu, system_information_class, system_information,
			length, return_length);
	};

	auto query_langid = [](vcpu&, emu_object<std::uint32_t> language_id,
		const std::string_view who) -> NTSTATUS
	{
		if (!language_id)
			return STATUS_INVALID_PARAMETER;

		language_id.write(langid_en_us);

		THREAD_LOG_INFO("{}() -> 0x{:04X}", who, langid_en_us);

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "QueryDefaultLocale",
		[query_langid](vcpu& cpu, const bool user_profile,
			emu_object<std::uint32_t> default_locale_id) -> NTSTATUS
		{
			THREAD_LOG_INFO("NtQueryDefaultLocale: user_profile={}", user_profile);
			return query_langid(cpu, default_locale_id, "NtQueryDefaultLocale");
		});

	state.redirect_ntzw(mod, "QueryDefaultUILanguage",
		[query_langid](vcpu& cpu, emu_object<std::uint32_t> default_ui_language) -> NTSTATUS
		{
			return query_langid(cpu, default_ui_language, "NtQueryDefaultUILanguage");
		});

	state.redirect_ntzw(mod, "QueryInstallUILanguage",
		[query_langid](vcpu& cpu, emu_object<std::uint32_t> install_ui_language) -> NTSTATUS
		{
			return query_langid(cpu, install_ui_language, "NtQueryInstallUILanguage");
		});

	// Nothing here sleeps or dims a display, so the request is recorded and the
	// previous state handed back is the one nothing ever changed it from.
	state.redirect_ntzw(mod, "SetThreadExecutionState",
		[](vcpu&, const std::uint32_t new_flags,
			emu_object<std::uint32_t> previous_flags) -> NTSTATUS
		{
			constexpr std::uint32_t es_continuous = 0x80000000;

			if (previous_flags)
				previous_flags.write(es_continuous);

			THREAD_LOG_INFO("NtSetThreadExecutionState(0x{:X}): nothing here sleeps", new_flags);

			return STATUS_SUCCESS;
		});

	// The emulator fetches from the same memory the guest writes, so an icache
	// that could go stale does not exist and there is nothing to flush.
	state.redirect_ntzw(mod, "FlushInstructionCache",
		[](vcpu&, const std::uint64_t process_handle, const addr_t base_address,
			const std::uint64_t length) -> NTSTATUS
		{
			THREAD_LOG_INFO("NtFlushInstructionCache(0x{:X}, 0x{:X}, {}): the emulator fetches "
				"from guest memory directly", process_handle, base_address, length);

			return STATUS_SUCCESS;
		});

	// A full barrier across every processor. Every cpu here shares one host
	// memory model already, so the barrier is implicit.
	state.redirect_ntzw(mod, "FlushProcessWriteBuffers", [](vcpu&)
	{
		THREAD_LOG_INFO("NtFlushProcessWriteBuffers()");
	});

	// One handle table, so a duplicate is a second handle onto the same object.
	// DUPLICATE_CLOSE_SOURCE closes the one it came from, which is the whole of
	// what the options decide here.
	state.redirect_ntzw(mod, "DuplicateObject",
		[st](vcpu&, const std::uint64_t source_process_handle,
			const std::uint64_t source_handle, const std::uint64_t target_process_handle,
			emu_object<std::uint64_t> target_handle, const std::uint32_t desired_access,
			const std::uint32_t handle_attributes, const std::uint32_t options) -> NTSTATUS
		{
			constexpr std::uint32_t duplicate_close_source = 0x1;
			constexpr std::uint32_t duplicate_same_access = 0x2;

			if (source_process_handle != current_process_handle
				|| target_process_handle != current_process_handle)
			{
				THREAD_LOG_WARN("NtDuplicateObject: there is one process here, so a handle can "
					"only be duplicated within it");
				return STATUS_INVALID_HANDLE;
			}

			auto& handles = st->sys_proc->handle_table();
			const auto entry = handles.lookup_handle(source_handle);

			if (!entry)
				return STATUS_INVALID_HANDLE;

			const auto access = (options & duplicate_same_access) ? entry->access : desired_access;

			st->objs.reference_object(entry->body_addr);
			const auto duplicate = handles.create_handle(entry->body_addr, access);

			if (target_handle)
				target_handle.write(duplicate);

			if (options & duplicate_close_source)
				handles.close_handle(source_handle);

			THREAD_LOG_INFO("NtDuplicateObject(0x{:X}, access=0x{:X}, attributes=0x{:X}, "
				"options=0x{:X}) -> 0x{:X}",
				source_handle, access, handle_attributes, options, duplicate);

			return STATUS_SUCCESS;
		});

	// A permanent object outlives its last handle because it is in the object
	// namespace; nothing here puts one there, so every object is already
	// temporary and this only has to agree.
	auto make_temporary = [st](vcpu&, const std::uint64_t handle) -> NTSTATUS
	{
		if (!st->sys_proc->handle_table().lookup_handle(handle))
			return STATUS_INVALID_HANDLE;

		THREAD_LOG_INFO("NtMakeTemporaryObject(0x{:X}): nothing here is permanent", handle);

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "MakeTemporaryObject", make_temporary);

	state.redirect_ntzw(mod, "QuerySystemInformation", query_system_information);
	state.redirect_ntzw(mod, "QuerySystemInformationEx", query_system_information_ex);

	// The NLS tables are files in System32, so they come out of the guest
	// filesystem -- and one that does not carry them says so rather than
	// handing back a mapping of nothing.
	auto map_nls_file = [st](vcpu& cpu, const std::string& path,
		emu_object<addr_t> base_out, const std::string_view who) -> NTSTATUS
	{
		const auto file = st->fs.open(path);

		if (!file)
		{
			THREAD_LOG_WARN("{}: {} is not in the guest filesystem", who, path);
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}

		auto& space = *cpu.curr_addr_space();
		const auto data = file->data();
		const auto base = space.alloc(data.size(), prot_rw);

		if (!base)
		{
			THREAD_LOG_ERR("{}: no room for {} ({} bytes)", who, path, data.size());
			return STATUS_NO_MEMORY;
		}

		space.write_mem(base, data.data(), data.size());

		if (base_out)
			base_out.write(base);

		THREAD_LOG_INFO("{}: mapped {} ({} bytes) at 0x{:X}", who, path, data.size(), base);

		return STATUS_SUCCESS;
	};

	state.redirect_ntzw(mod, "InitializeNlsFiles",
		[map_nls_file](vcpu& cpu, emu_object<addr_t> base_address,
			emu_object<std::uint32_t> default_locale_id,
			emu_object<std::int64_t> default_casing_table_size) -> NTSTATUS
		{
			// Without this file kernelbase cannot resolve LOCALE_INVARIANT and
			// its DllMain fails, taking the process down before it runs.
			const auto status = map_nls_file(cpu, std::string(system32_dir_narrow) + "locale.nls",
				base_address, "NtInitializeNlsFiles");

			if (status != STATUS_SUCCESS)
				return status;

			// en-US, as everything else here reports.
			if (default_locale_id)
				default_locale_id.write(0x0409);

			if (default_casing_table_size)
				default_casing_table_size.write(0);

			return STATUS_SUCCESS;
		});

	// NlsSectionCodePage is the only kind of section there is a file for.
	state.redirect_ntzw(mod, "GetNlsSectionPtr",
		[st, map_nls_file](vcpu& cpu, const std::uint32_t section_type,
			const std::uint32_t section_data, [[maybe_unused]] const addr_t context_data,
			emu_object<addr_t> section_pointer, emu_object<std::uint32_t> section_size) -> NTSTATUS
		{
			constexpr std::uint32_t nls_section_code_page = 11;

			if (section_type != nls_section_code_page)
			{
				THREAD_LOG_WARN("NtGetNlsSectionPtr: section type {} is not a code page",
					section_type);
				return STATUS_NOT_SUPPORTED;
			}

			const auto path = std::string(system32_dir_narrow) + "c_"
				+ std::to_string(section_data) + ".nls";

			const auto status = map_nls_file(cpu, path, section_pointer, "NtGetNlsSectionPtr");

			if (status != STATUS_SUCCESS)
				return status;

			if (section_size)
			{
				const auto file = st->fs.open(path);
				section_size.write(static_cast<std::uint32_t>(file ? file->size() : 0));
			}

			return STATUS_SUCCESS;
		});
}
