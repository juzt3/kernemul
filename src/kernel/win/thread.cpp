#include "thread.hpp"
#include "win_kernel.hpp"

// Coming off a cpu.
void win_thread::save(vcpu& cpu)
{
	thread::save(cpu);

	if (const auto* pcpu = emulator_ ? emulator_->per_cpu(cpu) : nullptr)
		pcpu->set_current_thread(0);

	if (!ethread_)
		return;

	// A thread that has not finished is going back on the queue. It is ready to
	// run again unless it asked to wait, which is the one thing a thread here
	// waits on: the scheduler will pass over it until its delay is up.
	const auto state = is_finished() ? Terminated : (is_sleeping() ? Waiting : Ready);

	set_thread_state(ethread_, state, false);

	if (state == Waiting)
		set_thread_wait_reason(ethread_, DelayExecution);
}

// And going on one.
void win_thread::restore(vcpu& cpu) const
{
	thread::restore(cpu);

	if (!emulator_)
		return;

	const auto* pcpu = emulator_->per_cpu(cpu);

	if (!pcpu)
		return;

	// The restore above put back whatever this thread last saw in the register
	// the KPCR is reached through, and that was the block of whichever cpu it
	// ran on before -- on x86-64 the register is the GS base, which a thread
	// carries because a user thread keeps its TEB there. A kernel thread has no
	// TEB to lose, so point it back at this cpu's block.
	if (is_system_thread())
		emulator_->set_pcr(cpu, pcpu->address());

	if (!ethread_)
		return;

	// Nothing else says which thread a cpu is running: the guest reads it out
	// of that cpu's own KPRCB.
	pcpu->set_current_thread(ethread_.address());

	set_thread_state(ethread_, Running, true);
	set_thread_processor(ethread_, static_cast<std::uint32_t>(cpu.id()));
	count_thread_switch(ethread_);
}
