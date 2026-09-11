#pragma once
#include "../emu/emu.hpp"
#include "process.hpp"
#include <algorithm>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

class thread
{
public:
	using id_type = std::uint32_t;

	thread(const id_type id, std::shared_ptr<process> proc,
		   const addr_t entry_point, const addr_t stack_ptr,
		   vcpu& cpu)
		: id_(id), process_(std::move(proc))
	{
		save(cpu);
		const auto a = cpu.arch();
		const auto regs = a->regs();
		const auto pc = a->pc();
		const auto sp = a->sp();

		for (std::size_t i = 0; i < regs.size(); ++i)
		{
			if (regs[i] == pc) values_[i] = entry_point;
			else if (regs[i] == sp) values_[i] = stack_ptr;
		}
	}

	void save(vcpu& cpu)
	{
		const auto regs = cpu.arch()->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
			values_[i] = cpu.reg(regs[i]);
	}

	void restore(vcpu& cpu) const
	{
		const auto regs = cpu.arch()->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
			cpu.reg(regs[i], values_[i]);
	}

	[[nodiscard]] id_type id() const noexcept { return id_; }
	[[nodiscard]] std::shared_ptr<process> proc() const noexcept { return process_; }

private:
	id_type id_;
	std::shared_ptr<class process> process_;
	std::vector<std::uint64_t> values_;
};

class thread_scheduler
{
public:
	explicit thread_scheduler(class emu& emu)
		: emu_(&emu) { }

	std::shared_ptr<thread> create_thread(std::shared_ptr<process> proc, const addr_t entry_point, const addr_t stack_ptr, vcpu& cpu)
	{
		std::scoped_lock lock(mtx_);
		const auto id = next_id_++;
		auto t = std::make_shared<thread>(id, std::move(proc), entry_point, stack_ptr, cpu);
		threads_[id] = t;
		ready_queue_.push_back(t);
		return t;
	}

	void terminate_thread(const thread::id_type id)
	{
		std::scoped_lock lock(mtx_);
		const auto it = threads_.find(id);
		if (it == threads_.end())
			return;

		std::erase(ready_queue_, it->second);
		threads_.erase(it);
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

		auto next = ready_queue_.front();
		ready_queue_.pop_front();
		next->restore(cpu);
		return next;
	}

	[[nodiscard]] std::shared_ptr<thread> find_thread(const thread::id_type id) const
	{
		std::scoped_lock lock(mtx_);
		const auto it = threads_.find(id);
		return it != threads_.end() ? it->second : nullptr;
	}

private:
	class emu* emu_;
	std::deque<std::shared_ptr<thread>> ready_queue_;
	std::map<thread::id_type, std::shared_ptr<thread>> threads_;
	thread::id_type next_id_ = 1;
	mutable std::mutex mtx_;
};
