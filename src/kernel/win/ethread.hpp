#pragma once
#include "../../emu/object.hpp"
#include "defs.hpp"
#include "types.hpp"

// The guest-side half of a thread. Windows keeps one ETHREAD per thread in
// kernel memory: it is what PsGetCurrentThread hands out, what a thread handle
// resolves to, and what the running cpu's KPRCB points at. The KTHREAD the
// scheduler cares about is the Tcb at the front of it, and a KTHREAD pointer
// and an ETHREAD pointer are the same address.

// Both heads sit inside the owning process's EPROCESS, at the front of which
// is its KPROCESS.
inline constexpr std::size_t kprocess_thread_list_off =
	offsetof(_EPROCESS, Pcb) + offsetof(_KPROCESS, ThreadListHead);
inline constexpr std::size_t eprocess_thread_list_off =
	offsetof(_EPROCESS, ThreadListHead);

inline kprocess_thread_list_t kprocess_thread_list(addr_space& space, const addr_t eprocess)
{
	return kprocess_thread_list_t(space, eprocess + kprocess_thread_list_off);
}

inline eprocess_thread_list_t eprocess_thread_list(addr_space& space, const addr_t eprocess)
{
	return eprocess_thread_list_t(space, eprocess + eprocess_thread_list_off);
}

// What a driver thread and a user thread get by default. A system thread runs
// at the bottom of the real-time range, a user thread at normal priority.
inline constexpr char system_thread_priority = 16;
inline constexpr char user_thread_priority = 8;

struct ethread_params
{
	// The owning process's EPROCESS. Zero if the guest has no view of the
	// process at all, which leaves the thread with no process to point at.
	addr_t eprocess = 0;
	addr_t start_addr = 0;
	// Zero for a kernel thread, which has no TEB.
	addr_t teb = 0;
	// The stack as Windows describes it: the limit is its low end, the base the
	// first byte past its top.
	addr_t stack_limit = 0;
	addr_t stack_base = 0;
	std::uint32_t process_id = 0;
	std::uint32_t thread_id = 0;
	bool system_thread = true;
};

inline _ETHREAD make_default_ethread(const ethread_params& p)
{
	const auto ptr = [](const addr_t a) { return reinterpret_cast<void*>(static_cast<std::uintptr_t>(a)); };

	_ETHREAD et{};
	auto& tcb = et.Tcb;

	// A thread is a waitable object, and the type in its dispatcher header is
	// how the guest tells what it is waiting on.
	tcb.Header.Type = static_cast<unsigned char>(ThreadObject);

	// The guest bounds-checks and unwinds against these, so they describe the
	// stack the thread was actually given. Nothing here switches stacks between
	// modes, so the kernel stack is that same stack.
	tcb.InitialStack = ptr(p.stack_base);
	tcb.StackBase = ptr(p.stack_base);
	tcb.StackLimit = ptr(p.stack_limit);
	tcb.KernelStack = ptr(p.stack_base);

	tcb.Teb = ptr(p.teb);

	// The KPROCESS is at the front of the EPROCESS, so one address serves both.
	tcb.Process = reinterpret_cast<_KPROCESS*>(static_cast<std::uintptr_t>(p.eprocess));
	tcb.ApcState.Process = tcb.Process;

	// Built but not yet on a cpu; the scheduler moves it on from here.
	tcb.State = static_cast<unsigned char>(Initialized);

	tcb.Priority = p.system_thread ? system_thread_priority : user_thread_priority;
	tcb.BasePriority = tcb.Priority;
	tcb.PreviousMode = static_cast<char>(p.system_thread ? KernelMode : UserMode);
	tcb.SystemThread = p.system_thread ? 1 : 0;
	tcb.ApcQueueable = 1;
	tcb.EnableStackSwap = 1;

	et.Cid.UniqueProcess = ptr(p.process_id);
	et.Cid.UniqueThread = ptr(p.thread_id);

	// Where the thread was told to start. Windows keeps the two separately
	// because a user thread's start routine is reached through a stub; here
	// both are the routine itself.
	et.StartAddress = ptr(p.start_addr);
	et.Win32StartAddress = ptr(p.start_addr);

	et.CreateTime.QuadPart = win_system_time();

	return et;
}

// The fields below change as the thread moves, so they are written one at a
// time rather than by putting the whole block down again: the guest owns this
// memory too, and a thread goes on and off a cpu far more often than anything
// else touches it.

inline void set_thread_state(const emu_object<_ETHREAD>& et, const KTHREAD_STATE state, const bool running)
{
	auto& space = *et.space();
	space.write_mem<unsigned char>(et.address() + offsetof(_ETHREAD, Tcb.State),
		static_cast<unsigned char>(state));
	space.write_mem<unsigned char>(et.address() + offsetof(_ETHREAD, Tcb.Running),
		running ? 1 : 0);
}

// Why a waiting thread is waiting, which is the only thing that tells the two
// kinds of Waiting apart once the state itself says no more than "not runnable".
inline void set_thread_wait_reason(const emu_object<_ETHREAD>& et, const KWAIT_REASON reason)
{
	et.space()->write_mem<unsigned char>(et.address() + offsetof(_ETHREAD, Tcb.WaitReason),
		static_cast<unsigned char>(reason));
}

// Which cpu the thread is on. Windows uses this to decide where to send an
// interrupt that has to reach a particular thread.
inline void set_thread_processor(const emu_object<_ETHREAD>& et, const std::uint32_t number)
{
	et.space()->write_mem<std::uint32_t>(et.address() + offsetof(_ETHREAD, Tcb.NextProcessor), number);
}

inline void count_thread_switch(const emu_object<_ETHREAD>& et)
{
	const auto at = et.address() + offsetof(_ETHREAD, Tcb.ContextSwitches);
	et.space()->write_mem<std::uint32_t>(at, et.space()->read_mem<std::uint32_t>(at) + 1);
}

inline void set_thread_exit_time(const emu_object<_ETHREAD>& et, const std::int64_t time)
{
	et.space()->write_mem<std::int64_t>(et.address() + offsetof(_ETHREAD, ExitTime), time);
}
