#include "nt_info_ops.hpp"
#include "../win_kernel.hpp"
#include "../process.hpp"
#include "../thread.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"
#include <chrono>
#include <random>
#include <atomic>

namespace
{

// win_ticks counts in ten million a second, so a counter delta and a time delta need no scaling.
constexpr std::int64_t perf_frequency = 10'000'000;

}

void modules::register_ntoskrnl_info_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;
	auto* m = &mod;

	state.redirect(mod, "KeQueryPerformanceCounter",
		[](vcpu&, emu_object<std::int64_t> frequency) -> std::int64_t
		{
			const auto now = std::chrono::steady_clock::now().time_since_epoch();
			const auto ticks = std::chrono::duration_cast<win_ticks>(now).count();

			if (frequency)
				frequency.write(perf_frequency);

			THREAD_LOG_INFO("KeQueryPerformanceCounter(frequency=0x{:X}) -> {}",
				frequency.address(), ticks);

			return ticks;
		});

	state.redirect(mod, "KeQueryTimeIncrement", [](vcpu&) -> std::uint32_t
	{
		THREAD_LOG_INFO("KeQueryTimeIncrement() -> {}", clock_increment_100ns);
		return clock_increment_100ns;
	});

	// The precise form reads the same clock as KUSER_SHARED_DATA, not the value cached there.
	auto system_time = [](vcpu&, emu_object<std::int64_t> current_time)
	{
		if (!current_time)
			return;

		const auto now = static_cast<std::int64_t>(win_system_time());
		current_time.write(now);

		THREAD_LOG_INFO("KeQuerySystemTime() -> {}", now);
	};

	state.redirect(mod, "KeQuerySystemTimePrecise", system_time);

	// Every cpu the emulator made is active and none can be taken offline.
	state.redirect(mod, "KeQueryActiveProcessorCount",
		[st](vcpu& cpu, emu_object<std::uint64_t> active_processors) -> std::uint32_t
		{
			const auto count = cpu.emu()->cpus().size();

			if (active_processors)
				active_processors.write(affinity_mask(count));

			st->kuser_shared_data.field(&_KUSER_SHARED_DATA::ActiveProcessorCount)
				.write(static_cast<std::uint32_t>(count));

			THREAD_LOG_INFO("KeQueryActiveProcessorCount(active_processors=0x{:X}) -> {}",
				active_processors.address(), count);

			return static_cast<std::uint32_t>(count);
		});

	// There is only ever one group here, so every other group number is empty rather than an error.
	state.redirect(mod, "KeQueryActiveProcessorCountEx",
		[](vcpu& cpu, const std::uint16_t group_number) -> std::uint32_t
		{
			constexpr std::uint16_t all_processor_groups = 0xFFFF;

			const auto count = (group_number == 0 || group_number == all_processor_groups)
				? static_cast<std::uint32_t>(cpu.emu()->cpus().size())
				: 0;

			THREAD_LOG_INFO("KeQueryActiveProcessorCountEx(group={}) -> {}",
				group_number, count);

			return count;
		});

	// With a single group the group relative index is the system wide one.
	state.redirect(mod, "KeGetCurrentProcessorNumberEx",
		[](vcpu& cpu, emu_object<_PROCESSOR_NUMBER> proc_number) -> std::uint32_t
		{
			const auto number = static_cast<std::uint32_t>(cpu.id());

			if (proc_number)
			{
				_PROCESSOR_NUMBER out{};
				out.Number = static_cast<std::uint8_t>(number);

				proc_number.write(out);
			}

			THREAD_LOG_INFO("KeGetCurrentProcessorNumberEx(0x{:X}) -> {}",
				proc_number.address(), number);

			return number;
		});

	// Interrupts are the third term on real Windows, never masked here, so that term is dropped.
	state.redirect(mod, "KeAreAllApcsDisabled", [st](vcpu& cpu) -> bool
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());
		const auto special = (t && t->ethread())
			? static_cast<std::int32_t>(t->special_apc_disable().read())
			: 0;

		auto* emulator = st->emulator();
		const auto irql = emulator ? emulator->irql(cpu) : passive_level;
		const bool disabled = special != 0 || irql != passive_level;

		THREAD_LOG_INFO("KeAreAllApcsDisabled(): special_apc_disable={}, irql={} -> {}",
			special, irql, disabled);

		return disabled;
	});

	state.redirect(mod, "PsGetCurrentProcess", [st](vcpu& cpu) -> addr_t
	{
		const auto t = cpu.thread();
		auto proc = t ? std::dynamic_pointer_cast<windows_process>(t->proc()) : nullptr;

		if (!proc)
			proc = st->sys_proc;

		const auto eprocess = proc->eprocess().address();

		if (!eprocess)
			THREAD_LOG_WARN("PsGetCurrentProcess: pid={} has no EPROCESS", proc->id());

		THREAD_LOG_INFO("PsGetCurrentProcess() -> 0x{:X} (pid={})", eprocess, proc->id());

		return eprocess;
	});

	// The same pointer under the name the io manager exports it as.
	state.redirect(mod, "IoGetCurrentProcess", [st](vcpu& cpu) -> addr_t
	{
		const auto t = cpu.thread();
		auto proc = t ? std::dynamic_pointer_cast<windows_process>(t->proc()) : nullptr;

		if (!proc)
			proc = st->sys_proc;

		const auto eprocess = proc->eprocess().address();

		if (!eprocess)
			THREAD_LOG_WARN("IoGetCurrentProcess: pid={} has no EPROCESS", proc->id());

		THREAD_LOG_INFO("IoGetCurrentProcess() -> 0x{:X} (pid={})", eprocess, proc->id());

		return eprocess;
	});

	state.redirect(mod, "PsGetProcessId",
		[](vcpu&, emu_object<_EPROCESS> process) -> addr_t
		{
			if (!process)
			{
				THREAD_LOG_WARN("PsGetProcessId: null process");
				return 0;
			}

			const auto id = guest_va(process.field(&_EPROCESS::UniqueProcessId).read());

			THREAD_LOG_INFO("PsGetProcessId(0x{:X}) -> {}", process.address(), id);

			return id;
		});

	state.redirect(mod, "PsGetThreadProcessId",
		[](vcpu&, emu_object<_ETHREAD> thread) -> addr_t
		{
			if (!thread)
			{
				THREAD_LOG_WARN("PsGetThreadProcessId: null thread");
				return 0;
			}

			// The thread's own copy of its client id is what it was created with, so the answer
			// is read back out of the guest rather than looked up among this process's threads.
			const auto id = guest_va(thread.field(&_ETHREAD::Cid)
				.field(&_CLIENT_ID::UniqueProcess).read());

			THREAD_LOG_INFO("PsGetThreadProcessId(0x{:X}) -> {}", thread.address(), id);

			return id;
		});

	// PsGetCurrentProcessId is the same export folded to one address on both architectures.
	auto current_process_id = [st](vcpu& cpu) -> addr_t
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		const auto id = (t && t->ethread())
			? guest_va(t->client_id().field(&_CLIENT_ID::UniqueProcess).read())
			: st->sys_proc->id();

		THREAD_LOG_INFO("PsGetCurrentProcessId() -> {}", id);

		return id;
	};

	state.redirect(mod, "PsGetCurrentThreadProcessId", current_process_id);
	state.redirect(mod, "PsGetCurrentProcessId", current_process_id);

	state.redirect(mod, "PsGetCurrentThreadId", [](vcpu& cpu) -> addr_t
	{
		const auto t = std::dynamic_pointer_cast<win_thread>(cpu.thread());

		const auto id = (t && t->ethread())
			? guest_va(t->client_id().field(&_CLIENT_ID::UniqueThread).read())
			: (cpu.thread() ? cpu.thread()->id() : 0);

		THREAD_LOG_INFO("PsGetCurrentThreadId() -> {}", id);

		return id;
	});

	state.redirect(mod, "RtlGetVersion",
		[st](vcpu& cpu, emu_object<_RTL_OSVERSIONINFOEXW> version_information) -> NTSTATUS
		{
			if (!version_information)
				return STATUS_INVALID_PARAMETER;

			const auto size = version_information
				.field(&_RTL_OSVERSIONINFOEXW::dwOSVersionInfoSize).read();

			if (size != sizeof(_RTL_OSVERSIONINFOW) && size != sizeof(_RTL_OSVERSIONINFOEXW))
			{
				THREAD_LOG_WARN("RtlGetVersion: dwOSVersionInfoSize={} is neither 0x{:X} nor 0x{:X}",
					size, sizeof(_RTL_OSVERSIONINFOW), sizeof(_RTL_OSVERSIONINFOEXW));
				return STATUS_INVALID_PARAMETER;
			}

			const auto shared = st->kuser_shared_data.read();

			_RTL_OSVERSIONINFOEXW out{};
			out.dwOSVersionInfoSize = size;
			out.dwMajorVersion = shared.NtMajorVersion;
			out.dwMinorVersion = shared.NtMinorVersion;
			out.dwBuildNumber = shared.NtBuildNumber;
			out.dwPlatformId = ver_platform_win32_nt;
			out.wProductType = ver_nt_workstation;

			// Only what the caller had room for: the EX fields sit past a plain RTL_OSVERSIONINFOW.
			cpu.curr_addr_space()->write_mem(version_information.address(), &out, size);

			THREAD_LOG_INFO("RtlGetVersion(0x{:X}) -> {}.{}.{}",
				version_information.address(), out.dwMajorVersion, out.dwMinorVersion,
				out.dwBuildNumber);

			return STATUS_SUCCESS;
		});

	// Every out parameter is optional, and the version that answers is the shared one the
	// rest of the emulated kernel already reports.
	state.redirect(mod, "PsGetVersion",
		[st](vcpu& cpu, emu_object<std::uint32_t> major_version,
			emu_object<std::uint32_t> minor_version,
			emu_object<std::uint32_t> build_number,
			emu_object<_UNICODE_STRING> csd_version) -> NTSTATUS
		{
			auto& space = *cpu.curr_addr_space();

			const auto shared = st->kuser_shared_data.read();

			if (major_version)
				major_version.write(shared.NtMajorVersion);

			if (minor_version)
				minor_version.write(shared.NtMinorVersion);

			if (build_number)
				build_number.write(shared.NtBuildNumber);

			if (csd_version)
			{
				// No service pack; an empty counted string is what a current build answers.
				_UNICODE_STRING out{};
				out.Length = 0;
				out.MaximumLength = 0;
				out.Buffer = nullptr;
				csd_version.write(out);
			}

			THREAD_LOG_INFO("PsGetVersion() -> {}.{}.{}", shared.NtMajorVersion,
				shared.NtMinorVersion, shared.NtBuildNumber);

			return STATUS_SUCCESS;
		});

	// The DDI version packs major, minor and build the same way NTDDI_VERSION does, and a caller
	// asking for one is asking whether the running kernel is at least as new as that build.
	state.redirect(mod, "RtlIsNtDdiVersionAvailable",
		[st](vcpu&, const std::uint32_t version) -> std::uint8_t
		{
			const auto shared = st->kuser_shared_data.read();

			const std::uint32_t current =
				(static_cast<std::uint32_t>(shared.NtMajorVersion) << 24)
				| (static_cast<std::uint32_t>(shared.NtMinorVersion) << 16)
				| (static_cast<std::uint32_t>(shared.NtBuildNumber) & 0xFFFF);

			const auto available = version <= current;

			THREAD_LOG_INFO("RtlIsNtDdiVersionAvailable(0x{:X}) -> {} (current 0x{:X})",
				version, available, current);

			return available;
		});

	// Only ntoskrnl is mapped here, so a hal routine comes back null.
	state.redirect(mod, "MmGetSystemRoutineAddress",
		[m](vcpu& cpu, emu_object<_UNICODE_STRING> system_routine_name) -> addr_t
		{
			const auto name = narrow_wstring(win::read_unicode_string(system_routine_name));

			if (name.empty())
				return 0;

			const auto addr = m->find_export(name);

			if (!addr)
				THREAD_LOG_WARN("MmGetSystemRoutineAddress: '{}' is not exported by {}",
					name, m->name);

			THREAD_LOG_INFO("MmGetSystemRoutineAddress('{}') -> 0x{:X}", name, addr.value_or(0));

			return addr.value_or(0);
		});

	// The caller's seed is the whole state: the same seed gives the same sequence, which is what
	// a caller that saves one to reproduce a run is relying on. Drawing from the host instead
	// would make every run of the same guest differ for a reason the guest never chose.
	state.redirect(mod, "RtlRandomEx",
		[](vcpu&, emu_object<std::uint32_t> seed) -> std::uint32_t
		{
			if (!seed)
				return 0;

			constexpr std::uint32_t multiplier = 0x7FFFFFED;
			constexpr std::uint32_t increment = 0x7FFFFFC3;
			constexpr std::uint32_t modulus = 0x7FFFFFFF;

			const auto value = static_cast<std::uint32_t>(
				(static_cast<std::uint64_t>(seed.read()) * multiplier + increment) % modulus);

			seed.write(value);

			THREAD_LOG_INFO("RtlRandomEx(seed=0x{:X}) -> {}", seed.address(), value);

			return value;
		});

	state.redirect(mod, "ExUuidCreate",
		[](vcpu& cpu, const addr_t uuid_out) -> NTSTATUS
		{
			if (!uuid_out)
				return STATUS_INVALID_PARAMETER;

			auto& space = *cpu.curr_addr_space();

			// A version 4 uuid: the clock is a steady count and a per-call sequence, and the node
			// is the destination, so two calls never name the same uuid while remaining bookkeeping
			// a guest can read back as itself.
			static std::atomic<std::uint64_t> sequence{ 0 };

			const auto now = static_cast<std::uint64_t>(
				std::chrono::steady_clock::now().time_since_epoch().count());
			const auto seq = sequence.fetch_add(1);

			std::uint64_t words[2]{
				now ^ seq,
				seq * 0x9E3779B97F4A7C15ull ^ uuid_out,
			};

			auto* const bytes = reinterpret_cast<std::uint8_t*>(words);
			bytes[6] = static_cast<std::uint8_t>((bytes[6] & 0x0F) | 0x40);
			bytes[8] = static_cast<std::uint8_t>((bytes[8] & 0x3F) | 0x80);

			space.write_mem(uuid_out, words);

			THREAD_LOG_INFO("ExUuidCreate(0x{:X}) -> {:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-"
				"{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
				uuid_out, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
				bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
				bytes[13], bytes[14], bytes[15]);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "RtlTimeToTimeFields",
		[](vcpu&, emu_object<std::int64_t> time, emu_object<_TIME_FIELDS> time_fields)
		{
			if (!time || !time_fields)
				return;

			namespace chrono = std::chrono;

			const auto since_1970 = win_ticks(time.read() - win_epoch_delta_100ns);
			const auto point = chrono::sys_time<win_ticks>(since_1970);
			const auto day = chrono::floor<chrono::days>(point);

			const chrono::year_month_day date(day);
			const chrono::hh_mm_ss clock(chrono::floor<chrono::milliseconds>(point - day));

			_TIME_FIELDS out{};
			out.Year = static_cast<short>(static_cast<int>(date.year()));
			out.Month = static_cast<short>(static_cast<unsigned>(date.month()));
			out.Day = static_cast<short>(static_cast<unsigned>(date.day()));
			out.Hour = static_cast<short>(clock.hours().count());
			out.Minute = static_cast<short>(clock.minutes().count());
			out.Second = static_cast<short>(clock.seconds().count());
			out.Milliseconds = static_cast<short>(clock.subseconds().count());
			out.Weekday = static_cast<short>(chrono::weekday(day).c_encoding());

			time_fields.write(out);

			THREAD_LOG_INFO("RtlTimeToTimeFields({}) -> {}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
				time.read(), out.Year, out.Month, out.Day, out.Hour, out.Minute,
				out.Second, out.Milliseconds);
		});
}
