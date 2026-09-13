#pragma once
#include <span>
#include "../emu/calling_conv.hpp"
#include "../emu/emu.hpp"
#include "../util/log.hpp"
#include "process.hpp"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <optional>
#include <memory>
#include <mutex>
#include <thread>

class thread
{
public:
	using id_type = std::uint32_t;
	using clock = std::chrono::steady_clock;
	using time_point = clock::time_point;

	thread(const id_type id, std::shared_ptr<process> proc,
		   const addr_t start_addr, const addr_t stack_ptr,
		   vcpu& cpu)
		: id_(id), process_(std::move(proc)),
		  values_(cpu.arch()->regs().size())
	{
		save(cpu);

		const auto a = cpu.arch();
		const auto regs = a->regs();

		for (std::size_t i = 0; i < regs.size(); ++i)
		{
			if (regs[i] == a->pc()) values_[i].gp = start_addr;
			else if (regs[i] == a->sp()) values_[i].gp = stack_ptr;
		}
	}

	virtual ~thread() = default;

	// The two halves of a context switch, and the only points a thread moves on
	// or off a cpu. Registers are not all a guest can see of which thread is
	// running, so an OS layer with more to say overrides these.
	virtual void save(vcpu& cpu)
	{
		const auto a = cpu.arch();
		const auto regs = a->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
			cpu.reg_read(regs[i], &values_[i], a->reg_size(regs[i]));
	}

	virtual void restore(vcpu& cpu) const
	{
		const auto a = cpu.arch();
		const auto regs = a->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
			cpu.reg_write(regs[i], &values_[i], a->reg_size(regs[i]));
	}

	void set_reg(vcpu& cpu, const reg_t r, const std::uint64_t value)
	{
		const auto regs = cpu.arch()->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
		{
			if (regs[i] == r) { values_[i].gp = value; return; }
		}
	}

	[[nodiscard]] std::uint64_t get_reg(vcpu& cpu, const reg_t r) const
	{
		const auto regs = cpu.arch()->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
		{
			if (regs[i] == r) return values_[i].gp;
		}
		return 0;
	}

	template <typename T>
	void set_reg_val(vcpu& cpu, const reg_t r, const T& value)
	{
		const auto regs = cpu.arch()->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
		{
			if (regs[i] == r) { std::memcpy(&values_[i], &value, sizeof(T)); return; }
		}
	}

	// A thread waits by staying on the ready queue with a time on it, rather
	// than by leaving the queue: nothing has to remember to put it back, and a
	// cpu looking for work passes over it until that time comes round.
	void sleep_for(const std::chrono::milliseconds ms) { sleep_until_ = clock::now() + ms; }
	[[nodiscard]] bool is_sleeping() const { return clock::now() < sleep_until_; }

	// Whether the scheduler may run this thread now. Sleeping is the only
	// reason the scheduler itself knows of; an OS layer with threads that park
	// on something -- a dispatcher object, a timer -- decides here, and is
	// handed a cpu so it can look at guest memory to do it.
	[[nodiscard]] virtual bool is_ready(vcpu&) { return !is_sleeping(); }
	[[nodiscard]] time_point sleep_until() const { return sleep_until_; }

	void finish() { finished_ = true; }
	[[nodiscard]] bool is_finished() const { return finished_; }

	// Which side of the kernel the thread runs on. Nothing in the scheduler
	// cares, but what a thread is doing reads differently depending on it, so
	// an OS layer that has the distinction says so -- see win_thread.
	[[nodiscard]] virtual bool is_user_mode() const { return false; }

	[[nodiscard]] id_type id() const noexcept { return id_; }
	[[nodiscard]] std::shared_ptr<process> proc() const noexcept { return process_; }

protected:
	id_type id_;
	std::shared_ptr<class process> process_;
	std::vector<reg_val> values_;

private:
	time_point sleep_until_{};
	bool finished_{false};
};

class thread_scheduler
{
public:
	thread_scheduler() = default;

	std::shared_ptr<thread> create_thread(vcpu& cpu, const addr_t start_addr,
		std::shared_ptr<process> proc, thread::id_type id,
		std::span<const std::uint64_t> args = {})
	{
		auto space = proc->addr_space();
		const addr_t stack_base = space->alloc(process::default_stack_size, prot_rw | prot_supervisor);
		const addr_t stack_top = stack_base + process::default_stack_size - process::stack_reserve;
		auto t = std::make_shared<thread>(id, std::move(proc), start_addr, stack_top, cpu);

		enqueue(cpu, t, args);
		return t;
	}

	// Admit a thread built elsewhere: a user thread needs a TEB and a stack in
	// its own process, so win_user_proc builds its own.
	void enqueue(vcpu& cpu, std::shared_ptr<thread> t,
		const std::span<const std::uint64_t> args = {})
	{
		const auto& conv = *cpu.emu()->call_conv();

		// Where the start routine returns to, which is how a cpu sees it finish.
		conv.set_ret_addr(cpu, *t, t->proc()->thread_exit_addr());

		// Before the push below, not after: the moment the thread is on the
		// queue another cpu can take it, and writing into the context of a
		// thread that is already running corrupts it.
		for (std::size_t i = 0; i < args.size(); ++i)
			conv.set_arg(cpu, *t, i, args[i]);

		{
			std::scoped_lock lock(mtx_);
			ready_queue_.push_back(std::move(t));
		}

		cv_.notify_one();
	}

	void remove(const thread::id_type id)
	{
		{
			std::scoped_lock lock(mtx_);
			std::erase_if(ready_queue_, [id](const auto& t) { return t->id() == id; });
		}

		cv_.notify_all();
	}

	// Bring every cpu's loop down, whether or not threads are left.
	void stop()
	{
		{
			std::scoped_lock lock(mtx_);
			stopped_ = true;
		}

		cv_.notify_all();
	}

	// Take the thread a cpu is running off it, without ending it. The cpu's
	// loop banks the thread and goes back to schedule(), which puts it on the
	// queue and picks whatever should run next -- possibly the same thread.
	static void yield_current(vcpu& cpu)
	{
		cpu.stop();
	}

	// The same, for a thread that asked to wait: it goes back on the queue
	// asleep, and no cpu picks it up again until its time is up. Waiting is the
	// whole point of the call that asks for this, so the thread gives up its cpu
	// now rather than running on to the end of its quantum.
	static void sleep_current(vcpu& cpu, const std::chrono::milliseconds ms)
	{
		if (const auto t = cpu.thread())
			t->sleep_for(ms);

		yield_current(cpu);
	}

	// A cpu's scheduling loop. It returns only once every thread everywhere has
	// finished: a cpu with nothing to do waits instead, since a thread running
	// on another cpu can create more work at any point.
	void run(vcpu& cpu)
	{
		std::shared_ptr<thread> curr;

		for (;;)
		{
			curr = schedule(cpu, std::move(curr));

			if (!curr)
				break;

			cpu.run();

			// Anything that stops a cpu without ending its thread is the
			// quantum running out: curr stays put, and the next schedule()
			// banks it and puts it back on the queue.
			if (!curr->is_finished())
				continue;

			curr->save(cpu);
			release(cpu);
			curr->proc()->terminate_thread(curr->id());
			curr = nullptr;
		}

		release(cpu);
	}

	// The next thread for this cpu, or nothing at all once the machine is done.
	// Waits while other cpus still hold threads that could produce more.
	std::shared_ptr<thread> schedule(vcpu& cpu, std::shared_ptr<thread> prev = nullptr)
	{
		std::unique_lock lock(mtx_);

		if (prev)
		{
			prev->save(cpu);
			cpu.set_thread(nullptr);
			ready_queue_.push_back(std::move(prev));
			cv_.notify_one();
		}

		for (;;)
		{
			if (stopped_ || nothing_left(cpu))
				return nullptr;

			if (const auto it = first_runnable(cpu); it != ready_queue_.end())
			{
				auto next = *it;
				ready_queue_.erase(it);

				// Off the queue and onto a cpu in one step, so no other cpu can
				// see the thread as gone from both. The cpu has to know which
				// thread it runs anyway: the exit stub's redirect has no other
				// way to tell who returned.
				cpu.set_thread(next);
				lock.unlock();

				resume(cpu, *next);
				return next;
			}

			// Every thread is either on another cpu or not ready. Waiting drops
			// the lock, so whoever holds them can get back in to requeue or
			// retire -- and whoever makes one of them ready notifies, which is
			// what gets this cpu back up when there is no time to wake at.
			if (const auto wake = next_wake())
				cv_.wait_until(lock, *wake);
			else
				cv_.wait(lock);
		}
	}

private:
	// The first thread on the queue that is ready to run. One that is not is
	// passed over rather than taken, so being the only thread left is no reason
	// to run it early: a cpu with nothing else to do waits instead.
	// Called with the lock held.
	std::deque<std::shared_ptr<thread>>::iterator first_runnable(vcpu& cpu)
	{
		return std::ranges::find_if(ready_queue_,
			[&cpu](const auto& t) { return t->is_ready(cpu); });
	}

	// When the first of the queued sleepers is due, which is the soonest this
	// cpu could have anything to do by itself. Nothing at all if none of them is
	// sleeping: a queued thread that is not ready and has no time on it is
	// parked on something another thread has to do, and that thread wakes the
	// cpus when it does it. Called with the lock held.
	std::optional<thread::time_point> next_wake() const
	{
		std::optional<thread::time_point> earliest;

		for (const auto& t : ready_queue_)
		{
			if (t->is_sleeping() && (!earliest || t->sleep_until() < *earliest))
				earliest = t->sleep_until();
		}

		return earliest;
	}

	// Put the thread's context on the cpu. Page tables are not part of that
	// context and processes share none of them, so the cpu follows the thread
	// into its own address space.
	static void resume(vcpu& cpu, const thread& t)
	{
		if (const auto space = t.proc()->addr_space(); cpu.curr_addr_space() != space)
			cpu.emu()->mem()->switch_to(cpu, space);

		t.restore(cpu);
	}

	// The cpu stops holding a thread, which is what lets the others finish.
	void release(vcpu& cpu)
	{
		{
			std::scoped_lock lock(mtx_);
			cpu.set_thread(nullptr);
		}

		cv_.notify_all();
	}

	// A thread is either queued or running on some cpu, so with none of either
	// left there is nothing to wait for: only a running thread creates threads.
	// Called with the lock held, which is what makes the two halves agree.
	bool nothing_left(vcpu& cpu) const
	{
		if (!ready_queue_.empty())
			return false;

		for (const auto& c : cpu.emu()->cpus())
		{
			if (c->thread())
				return false;
		}

		return true;
	}

	std::deque<std::shared_ptr<thread>> ready_queue_;
	mutable std::mutex mtx_;
	std::condition_variable cv_;
	bool stopped_ = false;
};
