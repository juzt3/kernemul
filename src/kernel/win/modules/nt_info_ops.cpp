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

namespace
{

// Ten million ticks a second is what win_ticks counts in, so a performance
// counter delta and a system time delta describe the same interval without
// either needing to be scaled.
constexpr std::int64_t perf_frequency = 10'000'000;

// NT's default on a machine whose timer it has not been asked to speed up. A
// driver divides by it to turn an interval into a count of clock ticks, so it
// has to be non-zero and plausible.
constexpr std::uint32_t clock_increment_100ns = 156250;

// A KAFFINITY names one group's worth of processors, and a group holds 64.
std::uint64_t affinity_mask(const std::size_t count)
{
	return count >= processor_group_size
		? ~std::uint64_t{0}
		: (std::uint64_t{1} << count) - 1;
}

}

// What a driver asks the kernel about itself: the clock, how many processors
// there are, which process is running, what Windows this is, and where a
// routine it wants to call by name lives.
void modules::register_ntoskrnl_info_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;
	auto* m = &mod;

	// A steady clock, because the guest times intervals with it and a wall
	// clock can step backwards under it.
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

	// The wall clock, which is what a driver stamps its own records with. The
	// precise form reads the same clock as KUSER_SHARED_DATA rather than the
	// value cached there, so the two never disagree by more than a tick.
	auto system_time = [](vcpu&, emu_object<std::int64_t> current_time)
	{
		if (!current_time)
			return;

		const auto now = static_cast<std::int64_t>(win_system_time());
		current_time.write(now);

		THREAD_LOG_INFO("KeQuerySystemTime() -> {}", now);
	};

	state.redirect(mod, "KeQuerySystemTimePrecise", system_time);

	// Every cpu the emulator made is active -- none of them can be taken
	// offline -- so the active count is just how many there are.
	state.redirect(mod, "KeQueryActiveProcessorCount",
		[st](vcpu& cpu, emu_object<std::uint64_t> active_processors) -> std::uint32_t
		{
			const auto count = cpu.emu()->cpus().size();

			if (active_processors)
				active_processors.write(affinity_mask(count));

			// The guest reads the count out of shared data as well, and the two
			// disagreeing is worse than either being wrong.
			st->kuser_shared_data.field(&_KUSER_SHARED_DATA::ActiveProcessorCount)
				.write(static_cast<std::uint32_t>(count));

			THREAD_LOG_INFO("KeQueryActiveProcessorCount(active_processors=0x{:X}) -> {}",
				active_processors.address(), count);

			return static_cast<std::uint32_t>(count);
		});

	// ALL_PROCESSOR_GROUPS asks for the machine-wide total. There is only ever
	// one group here, so every other group number is empty rather than an
	// error -- which is what a caller enumerating groups expects to find.
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

	// SpecialApcDisable covers the guarded regions, and the IRQL covers being
	// above passive. Interrupts are the third term on real Windows, and they
	// are never masked here -- nothing raises one -- so that term is dropped.
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

		// Before the scheduler owns a cpu there is no current thread, and the
		// only process there could be is the one the kernel started in.
		if (!proc)
			proc = st->sys_proc;

		const auto eprocess = proc->eprocess().address();

		if (!eprocess)
			THREAD_LOG_WARN("PsGetCurrentProcess: pid={} has no EPROCESS", proc->id());

		THREAD_LOG_INFO("PsGetCurrentProcess() -> 0x{:X} (pid={})", eprocess, proc->id());

		return eprocess;
	});

	// Read back out of the EPROCESS the caller already holds rather than
	// searched for: a driver can pass one it got from anywhere.
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

	// PsGetCurrentProcessId is the same export under a second name, folded to
	// one address on both architectures, so one handler serves both. It comes
	// from the thread's own ETHREAD rather than from its process, which is what
	// makes it answerable even when the process object is not set up.
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

	// The numbers come from KUSER_SHARED_DATA rather than from constants here,
	// so what a driver is told matches what it reads out of shared data itself.
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

			// Only what the caller said it had room for: the EX fields sit past
			// the end of a plain RTL_OSVERSIONINFOW.
			cpu.curr_addr_space()->write_mem(version_information.address(), &out, size);

			THREAD_LOG_INFO("RtlGetVersion(0x{:X}) -> {}.{}.{}",
				version_information.address(), out.dwMajorVersion, out.dwMinorVersion,
				out.dwBuildNumber);

			return STATUS_SUCCESS;
		});

	// The real one searches ntoskrnl's exports and then hal's. Only ntoskrnl is
	// mapped here, so a hal routine comes back null -- which the caller has to
	// handle anyway, since not finding the routine is why it asked.
	//
	// An address handed back is one the guest intends to call, and calling an
	// ntoskrnl address only works if something stands in for it. Saying which
	// ones do would mean listing every redirect; the unimplemented-function log
	// says it instead, at the point the guest actually jumps.
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

	// The documented seeded generator is gone from this build: it draws from
	// ExGenRandom and writes the result back over the caller's seed, so the
	// sequence is not reproducible from the seed the caller chose. Matching
	// that rather than the documentation, because a driver checking its own
	// seed afterwards sees what the real one left.
	state.redirect(mod, "RtlRandomEx",
		[](vcpu&, emu_object<std::uint32_t> seed) -> std::uint32_t
		{
			static std::mt19937 engine{std::random_device{}()};

			const auto value = engine() & 0x7FFFFFFF;

			if (seed)
				seed.write(value);

			THREAD_LOG_INFO("RtlRandomEx(seed=0x{:X}) -> {}", seed.address(), value);

			return value;
		});

	// A guest timestamp is 100ns ticks from 1601; std::chrono counts days from
	// 1970 and already knows how to break one into a calendar date, so the leap
	// year rules are its problem rather than this one's.
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
