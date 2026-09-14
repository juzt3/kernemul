#include "thread.hpp"
#include <utility>
#include <chrono>
#include "dispatcher.hpp"
#include "status.hpp"
#include "../../emu/calling_conv.hpp"
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

// Parking the thread. A timed wait is asleep until its deadline, so a cpu with
// nothing else to do sleeps that long too rather than looking at the thread
// again and again while it waits. An untimed wait has nothing to sleep until:
// it is released by the signal or not at all, and the signal wakes the cpus.
void win_thread::begin_wait(wait_state w)
{
	if (w.timed)
	{
		const auto remaining = std::max<std::int64_t>(
			0, w.deadline - static_cast<std::int64_t>(win_system_time()));

		// Rounded up: truncating here would arm the host sleep to run out
		// before the guest deadline it stands in for.
		sleep_for(std::chrono::ceil<std::chrono::milliseconds>(win_ticks(remaining)));
	}

	wait_ = std::move(w);
}

// Taking what a parked thread is waiting for. Whoever signalled one of its
// objects calls this, from a cpu, because deciding takes guest reads and the
// scheduler is in no position to make them.
bool win_thread::try_satisfy(addr_space& space)
{
	if (!wait_ || wait_->satisfied)
		return false;

	const auto self = ethread_.address();

	// WaitAll takes none of the objects until every one is available, which is
	// what keeps two threads from each taking half of what they need.
	std::size_t taken = wait_->objects.size();

	if (wait_->all)
	{
		for (const auto object : wait_->objects)
		{
			if (!win::is_signalled(space, object, self))
				return false;
		}
	}
	else
	{
		taken = wait_->objects.size() + 1;

		for (std::size_t i = 0; i < wait_->objects.size(); ++i)
		{
			if (win::is_signalled(space, wait_->objects[i], self))
			{
				taken = i;
				break;
			}
		}

		if (taken > wait_->objects.size())
			return false;
	}

	if (wait_->all)
	{
		for (const auto object : wait_->objects)
			win::take(space, object, self);

		wait_->status = STATUS_SUCCESS;
	}
	else
	{
		win::take(space, wait_->objects[taken], self);

		// WaitAny reports which object released it, and STATUS_WAIT_0 is zero,
		// so the index is the status.
		wait_->status = static_cast<NTSTATUS>(taken);
	}

	wait_->satisfied = true;

	return true;
}

// A wait naming no object is an alert wait, and this is the only thing that
// ends it. One arriving with nothing parked on it is kept, not dropped.
void win_thread::alert()
{
	if (wait_ && !wait_->satisfied && wait_->objects.empty())
	{
		wait_->status = STATUS_SUCCESS;
		wait_->satisfied = true;
		return;
	}

	alerted_ = true;
}

bool win_thread::take_alert()
{
	return std::exchange(alerted_, false);
}

std::uint32_t win_thread::suspend()
{
	const auto previous = suspend_count_++;

	if (ethread_)
		ethread_.field(&_ETHREAD::Tcb).field(&_KTHREAD::SuspendCount)
			.write(static_cast<char>(suspend_count_));

	return previous;
}

std::uint32_t win_thread::resume()
{
	const auto previous = suspend_count_;

	if (suspend_count_)
		--suspend_count_;

	if (ethread_)
		ethread_.field(&_ETHREAD::Tcb).field(&_KTHREAD::SuspendCount)
			.write(static_cast<char>(suspend_count_));

	return previous;
}

// A parked thread runs again once its wait has been satisfied by whoever
// signalled it, or once it has waited as long as it was told to. Both are
// answered from what the wait already holds: nothing here touches guest memory,
// because the scheduler asks this with no thread on the cpu.
bool win_thread::is_ready(vcpu& cpu)
{
	// Ahead of the wait, so a thread suspended while parked stays off the cpu.
	if (suspend_count_)
		return false;

	if (!wait_)
		return thread::is_ready(cpu);

	const auto conv = cpu.emu()->call_conv();

	const auto finish = [&](const NTSTATUS status)
	{
		conv->set_ret(cpu, *this, status);

		// A timed wait slept until its deadline. Leaving that behind would
		// make a thread released early look asleep to every later look.
		sleep_for(std::chrono::milliseconds(0));
		wait_.reset();
	};

	if (wait_->satisfied)
	{
		finish(wait_->status);
		return true;
	}

	if (wait_->timed)
	{
		const auto remaining = wait_->deadline - static_cast<std::int64_t>(win_system_time());

		if (remaining <= 0)
		{
			finish(STATUS_TIMEOUT);
			return true;
		}

		// Still time to go, so put it back to sleep for what is left of it.
		// The deadline is guest time and the sleep the scheduler paces itself
		// by is host time, so the two do not run out at the same instant: a cpu
		// that wakes even a tick early would otherwise find this thread neither
		// ready nor sleeping, and go back to waiting with no time to wake at --
		// which is nothing at all to wake it when it is the last thread left.
		sleep_for(std::chrono::ceil<std::chrono::milliseconds>(win_ticks(remaining)));
	}

	return false;
}
