#pragma once
#include "../thread_scheduler.hpp"
#include "ethread.hpp"
#include "process.hpp"
#include "user_setup.hpp"

class windows_emulator;

// A Windows thread. Its registers are the scheduler's business; everything else
// the guest can see about it lives in the ETHREAD below, which the two halves
// of a context switch keep in step with where the thread actually is.
class win_thread : public thread
{
public:
	win_thread(const id_type id, std::shared_ptr<windows_process> proc,
		const addr_t start_addr, const addr_t stack_base,
		const std::size_t stack_size, vcpu& cpu)
		:	thread(id, std::move(proc), start_addr,
				stack_base + stack_size - process::stack_reserve, cpu),
			stack_low_(stack_base), stack_size_(stack_size) {}

	// Registers plus the guest-visible half: which cpu's KPRCB points at this
	// thread, and what its ETHREAD says it is doing.
	void save(vcpu& cpu) override;
	void restore(vcpu& cpu) const override;

	// Built once the thread has its stack and, for a user thread, its TEB --
	// see windows_process::setup_ethread.
	void set_ethread(emu_object<_ETHREAD> et) { ethread_ = std::move(et); }
	[[nodiscard]] const emu_object<_ETHREAD>& ethread() const { return ethread_; }

	void set_emulator(windows_emulator* e) { emulator_ = e; }

	// The count KeEnterCriticalRegion drives down and KeLeaveCriticalRegion
	// back up. Kernel APCs are disabled for this thread while it is negative,
	// and the guest checks it directly as well as through KeAreAllApcsDisabled.
	[[nodiscard]] auto kernel_apc_disable() const
	{
		return ethread_.field(&_ETHREAD::Tcb).field(&_KTHREAD::KernelApcDisable);
	}

	// The guarded-region equivalent, which holds off special kernel APCs too.
	// KeAreAllApcsDisabled reads this one rather than the count above.
	[[nodiscard]] auto special_apc_disable() const
	{
		return ethread_.field(&_ETHREAD::Tcb).field(&_KTHREAD::SpecialApcDisable);
	}

	// Cid.UniqueProcess -- which process the guest believes this thread runs
	// in, as opposed to which process object the emulator hung it off.
	[[nodiscard]] auto client_id() const
	{
		return ethread_.field(&_ETHREAD::Cid);
	}

	// The stack as Windows names it: the limit is its low end, the base the
	// first byte past its top.
	[[nodiscard]] addr_t stack_limit() const { return stack_low_; }
	[[nodiscard]] addr_t stack_base() const { return stack_low_ + stack_size_; }

	// Only a user thread builds one, and having one is what separates the two
	// wherever else the difference matters.
	[[nodiscard]] const emu_object<_TEB64>& teb() const { return teb_; }
	[[nodiscard]] bool is_system_thread() const { return !teb_; }

	[[nodiscard]] bool is_user_mode() const override { return !is_system_thread(); }

protected:
	addr_t stack_low_;
	std::size_t stack_size_;
	emu_object<_TEB64> teb_;
	emu_object<_ETHREAD> ethread_;
	windows_emulator* emulator_ = nullptr;
};

class win_user_thread : public win_thread
{
public:
	win_user_thread(id_type id, std::shared_ptr<windows_process> proc, win_user_mem& mem,
		addr_t start_addr, addr_t stack_base, std::size_t stack_size,
		vcpu& cpu)
		:	win_thread(id, proc, start_addr, stack_base, stack_size, cpu)
	{
		const auto teb_va = mem.alloc(teb64_alloc_size, prot_rw);
		teb_ = emu_object<_TEB64>(mem.space(), teb_va);
		teb_.write(make_default_teb(teb_va, stack_base, stack_size,
			proc->id(), id, proc->peb().address()));
	}
};

class win_kernel_thread : public win_thread
{
public:
	using win_thread::win_thread;
};
