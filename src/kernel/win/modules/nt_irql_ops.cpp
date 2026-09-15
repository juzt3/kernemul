#include "nt_irql_ops.hpp"
#include "../win_kernel.hpp"
#include "../per_cpu.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"

namespace
{

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

// A redirect runs with this cpu stopped, so no lock contends; what is left is the IRQL it leaves.
void modules::register_ntoskrnl_irql_ops(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "KeGetCurrentIrql", [st](vcpu& cpu) -> irql_t
	{
		return current(*st, cpu);
	});

	state.redirect(mod, "KeRaiseIrql",
		[st](vcpu& cpu, const irql_t new_irql, emu_object<irql_t> old_irql_out)
		{
			const auto old = raise_to(*st, cpu, new_irql);

			if (old_irql_out)
				old_irql_out.write(old);
		});

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

	state.redirect(mod, "KeRaiseIrqlToSynchLevel", [st](vcpu& cpu) -> irql_t
	{
		return raise_to(*st, cpu, dispatch_level);
	});

	state.redirect(mod, "KeAcquireSpinLockRaiseToDpc",
		[st](vcpu& cpu, const addr_t spin_lock) -> irql_t
		{
			THREAD_LOG_INFO("KeAcquireSpinLockRaiseToDpc(lock=0x{:X})", spin_lock);
			return raise_to(*st, cpu, dispatch_level);
		});

	state.redirect(mod, "KeReleaseSpinLock",
		[st](vcpu& cpu, const addr_t spin_lock, const irql_t new_irql)
		{
			THREAD_LOG_INFO("KeReleaseSpinLock(lock=0x{:X}, new_irql={})", spin_lock, new_irql);
			raise_to(*st, cpu, new_irql);
		});

	state.redirect(mod, "KeAcquireSpinLockAtDpcLevel", [](vcpu&, const addr_t spin_lock)
	{
		THREAD_LOG_INFO("KeAcquireSpinLockAtDpcLevel(lock=0x{:X})", spin_lock);
	});

	state.redirect(mod, "KeReleaseSpinLockFromDpcLevel", [](vcpu&, const addr_t spin_lock)
	{
		THREAD_LOG_INFO("KeReleaseSpinLockFromDpcLevel(lock=0x{:X})", spin_lock);
	});

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
