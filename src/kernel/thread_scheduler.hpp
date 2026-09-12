#pragma once
#include "../emu/emu.hpp"
#include "process.hpp"
#include <algorithm>
#include <chrono>
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

	void save(vcpu& cpu)
	{
		const auto a = cpu.arch();
		const auto regs = a->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
			cpu.reg_read(regs[i], &values_[i], a->reg_size(regs[i]));
	}

	void restore(vcpu& cpu) const
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

		std::scoped_lock lock(mtx_);
		ready_queue_.push_back(t);
		return t;
	}

	void enqueue(std::shared_ptr<thread> t)
	{
		std::scoped_lock lock(mtx_);
		ready_queue_.push_back(std::move(t));
	}

	void remove(const thread::id_type id)
	{
		std::scoped_lock lock(mtx_);
		std::erase_if(ready_queue_, [id](const auto& t) { return t->id() == id; });
	}

	std::shared_ptr<thread> schedule(vcpu& cpu, std::shared_ptr<thread> prev = nullptr)
	{
		std::scoped_lock lock(mtx_);

		if (prev)
		{
			prev->save(cpu);
			ready_queue_.push_back(std::move(prev));
		}

		if (ready_queue_.empty())
			return nullptr;

		for (auto it = ready_queue_.begin(); it != ready_queue_.end(); ++it)
		{
			if (!(*it)->is_sleeping())
			{
				auto next = *it;
				ready_queue_.erase(it);
				next->restore(cpu);
				return next;
			}
		}

		auto earliest = std::min_element(ready_queue_.begin(), ready_queue_.end(),
			[](const auto& a, const auto& b) { return a->sleep_until() < b->sleep_until(); });

		std::this_thread::sleep_until((*earliest)->sleep_until());

		auto next = *earliest;
		ready_queue_.erase(earliest);
		next->restore(cpu);
		return next;
	}

private:
	std::deque<std::shared_ptr<thread>> ready_queue_;
	mutable std::mutex mtx_;
};
