#pragma once
#include "../emu/emu.hpp"
#include "process.hpp"
#include <algorithm>
#include <deque>
#include <memory>
#include <mutex>

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
		const auto pc = a->pc();
		const auto sp = a->sp();

		for (std::size_t i = 0; i < regs.size(); ++i)
		{
			if (regs[i] == pc) values_[i] = start_addr;
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

	void set_reg(vcpu& cpu, const reg_t r, const std::uint64_t value)
	{
		const auto regs = cpu.arch()->regs();
		for (std::size_t i = 0; i < regs.size(); ++i)
		{
			if (regs[i] == r) { values_[i] = value; return; }
		}
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

	std::shared_ptr<thread> create_thread(vcpu& cpu, const addr_t start_addr, std::shared_ptr<process> proc)
	{
		auto space = proc->addr_space();
		const addr_t stack_base = space->alloc(process::default_stack_size, prot_rw | prot_supervisor);
		const addr_t stack_top = stack_base + process::default_stack_size - 0x100;
		const auto id = process::alloc_thread_id();
		auto t = std::make_shared<thread>(id, std::move(proc), start_addr, stack_top, cpu);

		std::scoped_lock lock(mtx_);
		ready_queue_.push_back(t);
		return t;
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

		auto next = ready_queue_.front();
		ready_queue_.pop_front();
		next->restore(cpu);
		return next;
	}

private:
	class emu* emu_;
	std::deque<std::shared_ptr<thread>> ready_queue_;
	mutable std::mutex mtx_;
};
