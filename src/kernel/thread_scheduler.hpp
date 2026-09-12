#pragma once
#include "../emu/calling_conv.hpp"
#include "../emu/emu.hpp"
#include "../util/log.hpp"
#include "process.hpp"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>

class thread
{
public:
	using id_type = std::uint32_t;

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

	void sleep_for(std::chrono::milliseconds ms) { sleep_until_ = clock::now() + ms; }
	bool is_sleeping() const { return clock::now() < sleep_until_; }
	auto sleep_until() const { return sleep_until_; }

	void finish() { finished_ = true; }
	[[nodiscard]] bool is_finished() const { return finished_; }

	[[nodiscard]] id_type id() const noexcept { return id_; }
	[[nodiscard]] std::shared_ptr<process> proc() const noexcept { return process_; }

protected:
	id_type id_;
	std::shared_ptr<class process> process_;
	std::vector<reg_val> values_;

private:
	using clock = std::chrono::steady_clock;

	clock::time_point sleep_until_{};
	bool finished_{false};
};

class thread_scheduler
{
public:
	thread_scheduler() = default;

	std::shared_ptr<thread> create_thread(vcpu& cpu, const addr_t start_addr,
		std::shared_ptr<process> proc, thread::id_type id)
	{
		auto space = proc->addr_space();
		const addr_t stack_base = space->alloc(process::default_stack_size, prot_rw | prot_supervisor);
		const addr_t stack_top = stack_base + process::default_stack_size - process::stack_reserve;
		auto t = std::make_shared<thread>(id, std::move(proc), start_addr, stack_top, cpu);

		enqueue(cpu, t);
		return t;
	}

	// Admit a thread built elsewhere: a user thread needs a TEB and a stack in
	// its own process, so win_user_proc builds its own.
	void enqueue(vcpu& cpu, std::shared_ptr<thread> t)
	{
		// Where the start routine returns to, which is how a cpu sees it finish.
		cpu.emu()->call_conv()->set_ret_addr(cpu, *t, t->proc()->thread_exit_addr());

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

			const auto it = std::ranges::find_if(ready_queue_,
				[](const auto& t) { return !t->is_sleeping(); });

			if (it != ready_queue_.end())
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

			// Every thread is either on another cpu or asleep. Waiting drops the
			// lock, so whoever holds them can get back in to requeue or retire.
			if (ready_queue_.empty())
			{
				cv_.wait(lock);
			}
			else
			{
				const auto earliest = std::ranges::min_element(ready_queue_, {},
					[](const auto& t) { return t->sleep_until(); });

				cv_.wait_until(lock, (*earliest)->sleep_until());
			}
		}
	}

private:
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
