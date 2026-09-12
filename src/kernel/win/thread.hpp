#pragma once
#include "../thread_scheduler.hpp"
#include "process.hpp"
#include "eb.hpp"

class win_thread : public thread
{
public:
	using thread::thread;
};

class win_user_thread : public win_thread
{
public:
	win_user_thread(id_type id, std::shared_ptr<windows_process> proc,
		addr_t start_addr, addr_t stack_base, std::size_t stack_size,
		vcpu& cpu)
		:	win_thread(id, proc, start_addr, stack_base + stack_size - process::stack_reserve, cpu)
	{
		auto& space = *proc->addr_space();
		const auto teb_va = space.alloc(teb64_alloc_size, prot_rw);
		teb_ = emu_object<_TEB64>(space, teb_va);
		teb_.write(make_default_teb(teb_va, stack_base, stack_size,
			proc->id(), id, proc->peb().address()));
	}

	const emu_object<_TEB64>& teb() const { return teb_; }

private:
	emu_object<_TEB64> teb_;
};

class win_kernel_thread : public win_thread
{
public:
	using win_thread::win_thread;
};
