#include "nt_ex_ops.hpp"
#include "../win_kernel.hpp"
#include "../status.hpp"
#include "../string.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include "../../../util/string.hpp"

// The executive odds and ends: the local clock, a work item, an access
// violation a driver raises on itself, and the firmware variables.
void modules::register_ntoskrnl_ex_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	// Local time is system time less the timezone bias, which the guest also
	// reads out of shared data for itself -- so it comes from there rather than
	// from the host's own idea of a timezone, and the two cannot disagree.
	state.redirect(mod, "ExSystemTimeToLocalTime",
		[st](vcpu&, emu_object<std::int64_t> system_time, emu_object<std::int64_t> local_time)
		{
			if (!system_time || !local_time)
				return;

			const auto bias_low = st->kuser_shared_data.field(&_KUSER_SHARED_DATA::TimeZoneBias)
				.field(&_KSYSTEM_TIME::LowPart).read();
			const auto bias_high = st->kuser_shared_data.field(&_KUSER_SHARED_DATA::TimeZoneBias)
				.field(&_KSYSTEM_TIME::High1Time).read();

			const auto bias = (static_cast<std::int64_t>(bias_high) << 32) | bias_low;
			const auto local = system_time.read() - bias;

			local_time.write(local);

			THREAD_LOG_INFO("ExSystemTimeToLocalTime({}) -> {} (bias {})",
				system_time.read(), local, bias);
		});

	// A work item runs on a pooled worker thread in real Windows. There is no
	// pool here, so it gets a system thread of its own -- which is the same
	// thing from the routine's side: it runs at passive level, in the system
	// process, after the caller has moved on.
	state.redirect(mod, "ExQueueWorkItem",
		[st](vcpu& cpu, emu_object<_WORK_QUEUE_ITEM> work_item, const std::uint32_t queue_type)
		{
			if (!work_item)
			{
				THREAD_LOG_ERR("ExQueueWorkItem: null work item");
				return;
			}

			const auto routine = guest_va(work_item.field(&_WORK_QUEUE_ITEM::WorkerRoutine).read());
			const auto parameter = guest_va(work_item.field(&_WORK_QUEUE_ITEM::Parameter).read());

			if (!routine)
			{
				THREAD_LOG_ERR("ExQueueWorkItem: 0x{:X} has no worker routine", work_item.address());
				return;
			}

			auto t = st->sys_proc->create_thread(cpu, routine);
			cpu.emu()->call_conv()->set_arg(cpu, *t, 0, parameter);

			THREAD_LOG_INFO("ExQueueWorkItem(item=0x{:X}, queue={}): routine 0x{:X}(0x{:X}) "
				"runs as tid={}", work_item.address(), queue_type, routine, parameter, t->id());
		});

	// Raises STATUS_ACCESS_VIOLATION at the caller and never returns. Nothing
	// here delivers a software exception into the guest, and a driver calling
	// this has already decided it cannot go on -- so the thread ends where the
	// unwind would have taken it, rather than returning from a routine that
	// cannot return.
	state.redirect(mod, "ExRaiseAccessViolation", [](vcpu& cpu)
	{
		THREAD_LOG_ERR("ExRaiseAccessViolation: nothing delivers the exception, so the thread "
			"ends here");

		if (const auto t = cpu.thread())
			t->finish();

		cpu.stop();
	});

	// The real one refuses outright on a machine whose firmware is not UEFI,
	// and nothing here is: no variable store exists to read from. So this is
	// the status the guest would get on such a machine rather than an invented
	// failure, and a driver probing for firmware support takes the same path it
	// would take on real hardware without it.
	state.redirect(mod, "ExGetFirmwareEnvironmentVariable",
		[](vcpu&, emu_object<_UNICODE_STRING> variable_name, emu_object<void> vendor_guid,
			[[maybe_unused]] const addr_t value, emu_object<std::uint32_t> value_length,
			[[maybe_unused]] emu_object<std::uint32_t> attributes) -> NTSTATUS
		{
			const auto name = narrow_wstring(win::read_unicode_string(variable_name));

			THREAD_LOG_WARN("ExGetFirmwareEnvironmentVariable('{}', guid=0x{:X}): no uefi "
				"firmware to read from", name, vendor_guid.address());

			if (value_length)
				value_length.write(0);

			return STATUS_NOT_IMPLEMENTED;
		});
}
