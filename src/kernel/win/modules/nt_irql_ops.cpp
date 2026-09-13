#include "nt_irql_ops.hpp"
#include "../win_kernel.hpp"
#include "../per_cpu.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"

namespace
{

// The emulator is attached to the kernel state only after the modules have been
// registered, so a handler looks it up when it runs rather than capturing it
// when it is installed.
irql_t raise_to(win_kernel_state& state, vcpu& cpu, const irql_t irql)
{
	auto* emulator = state.emulator();
	return emulator ? emulator->set_irql(cpu, irql) : passive_level;
}

irql_t current(win_kernel_state& state, vcpu& cpu)
{
	auto* emulator = state.emulator();
	return emulator ? emulator->irql(cpu) : passive_level;
}

}

// IRQL, and the spin locks whose visible effect is to move it. Nothing here can
// be contended: a spin lock guards a section against another processor, and a
// redirect runs with this cpu stopped, so whatever the guest is locking against
// is not running either. What is left of a lock is the level it leaves the cpu
// at, and the guest does read that back -- it asserts on its own IRQL far more
// often than it races anything.
void modules::register_ntoskrnl_irql_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "KeGetCurrentIrql", [st](vcpu& cpu) -> irql_t
	{
		return current(*st, cpu);
	});

	// KeRaiseIrql(KIRQL NewIrql, PKIRQL OldIrql)
	state.redirect(mod, "KeRaiseIrql",
		[st](vcpu& cpu, const irql_t new_irql, emu_object<irql_t> old_irql_out)
		{
			const auto old = raise_to(*st, cpu, new_irql);

			if (old_irql_out)
				old_irql_out.write(old);
		});

	// The same raise, with the old level returned rather than written out.
	state.redirect(mod, "KfRaiseIrql", [st](vcpu& cpu, const irql_t new_irql) -> irql_t
	{
		return raise_to(*st, cpu, new_irql);
	});

	state.redirect(mod, "KeLowerIrql", [st](vcpu& cpu, const irql_t new_irql)
	{
		raise_to(*st, cpu, new_irql);
	});

	state.redirect(mod, "KfLowerIrql", [st](vcpu& cpu, const irql_t new_irql)
	{
		raise_to(*st, cpu, new_irql);
	});

	state.redirect(mod, "KeRaiseIrqlToDpcLevel", [st](vcpu& cpu) -> irql_t
	{
		return raise_to(*st, cpu, dispatch_level);
	});

	// Synchronisation level is above dispatch on a multiprocessor build, but
	// only so a scheduler lock outranks a dpc. Neither is enforced here, so the
	// two land on the same number.
	state.redirect(mod, "KeRaiseIrqlToSynchLevel", [st](vcpu& cpu) -> irql_t
	{
		return raise_to(*st, cpu, dispatch_level);
	});

	// KeAcquireSpinLock is a macro over this one: the lock is taken at dispatch
	// level and the caller is handed the level it was at.
	state.redirect(mod, "KeAcquireSpinLockRaiseToDpc",
		[st](vcpu& cpu, const addr_t spin_lock) -> irql_t
		{
			THREAD_LOG_INFO("KeAcquireSpinLockRaiseToDpc(lock=0x{:X})", spin_lock);
			return raise_to(*st, cpu, dispatch_level);
		});

	// KeReleaseSpinLock(PKSPIN_LOCK SpinLock, KIRQL NewIrql)
	state.redirect(mod, "KeReleaseSpinLock",
		[st](vcpu& cpu, const addr_t spin_lock, const irql_t new_irql)
		{
			THREAD_LOG_INFO("KeReleaseSpinLock(lock=0x{:X}, new_irql={})", spin_lock, new_irql);
			raise_to(*st, cpu, new_irql);
		});

	// The at-dpc-level pair leave the IRQL alone: the caller is already there,
	// and saying so is the whole of what separates them from the pair above.
	state.redirect(mod, "KeAcquireSpinLockAtDpcLevel", [](vcpu&, const addr_t spin_lock)
	{
		THREAD_LOG_INFO("KeAcquireSpinLockAtDpcLevel(lock=0x{:X})", spin_lock);
	});

	state.redirect(mod, "KeReleaseSpinLockFromDpcLevel", [](vcpu&, const addr_t spin_lock)
	{
		THREAD_LOG_INFO("KeReleaseSpinLockFromDpcLevel(lock=0x{:X})", spin_lock);
	});

	// The executive's reader/writer spin locks. Shared and exclusive differ
	// only in who else may hold the lock, which here is nobody either way.
	state.redirect(mod, "ExAcquireSpinLockShared",
		[st](vcpu& cpu, const addr_t spin_lock) -> irql_t
		{
			THREAD_LOG_INFO("ExAcquireSpinLockShared(lock=0x{:X})", spin_lock);
			return raise_to(*st, cpu, dispatch_level);
		});

	state.redirect(mod, "ExAcquireSpinLockExclusive",
		[st](vcpu& cpu, const addr_t spin_lock) -> irql_t
		{
			THREAD_LOG_INFO("ExAcquireSpinLockExclusive(lock=0x{:X})", spin_lock);
			return raise_to(*st, cpu, dispatch_level);
		});

	state.redirect(mod, "ExReleaseSpinLockShared",
		[st](vcpu& cpu, const addr_t spin_lock, const irql_t old_irql)
		{
			THREAD_LOG_INFO("ExReleaseSpinLockShared(lock=0x{:X}, old_irql={})", spin_lock, old_irql);
			raise_to(*st, cpu, old_irql);
		});

	state.redirect(mod, "ExReleaseSpinLockExclusive",
		[st](vcpu& cpu, const addr_t spin_lock, const irql_t old_irql)
		{
			THREAD_LOG_INFO("ExReleaseSpinLockExclusive(lock=0x{:X}, old_irql={})", spin_lock, old_irql);
			raise_to(*st, cpu, old_irql);
		});

	state.redirect(mod, "ExAcquireSpinLockExclusiveAtDpcLevel", [](vcpu&, const addr_t spin_lock)
	{
		THREAD_LOG_INFO("ExAcquireSpinLockExclusiveAtDpcLevel(lock=0x{:X})", spin_lock);
	});

	state.redirect(mod, "ExReleaseSpinLockExclusiveFromDpcLevel", [](vcpu&, const addr_t spin_lock)
	{
		THREAD_LOG_INFO("ExReleaseSpinLockExclusiveFromDpcLevel(lock=0x{:X})", spin_lock);
	});
}
