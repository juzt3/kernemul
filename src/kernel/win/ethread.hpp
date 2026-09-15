#pragma once
#include "../../emu/object.hpp"
#include "defs.hpp"
#include "types.hpp"


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

// A system thread runs at the bottom of the real-time range, a user thread at normal priority.
inline constexpr char system_thread_priority = 16;
inline constexpr char user_thread_priority = 8;

struct ethread_params
{
	// Zero if the guest has no view of the process at all.
	addr_t eprocess = 0;
	addr_t start_addr = 0;
	// Zero for a kernel thread, which has no TEB.
	addr_t teb = 0;
	// The limit is the stack's low end, the base the first byte past its top.
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

	tcb.Header.Type = static_cast<unsigned char>(ThreadObject);

	// Nothing here switches stacks between modes, so the kernel stack is that same stack.
	tcb.InitialStack = ptr(p.stack_base);
	tcb.StackBase = ptr(p.stack_base);
	tcb.StackLimit = ptr(p.stack_limit);
	tcb.KernelStack = ptr(p.stack_base);

	tcb.Teb = ptr(p.teb);

	tcb.Process = reinterpret_cast<_KPROCESS*>(static_cast<std::uintptr_t>(p.eprocess));
	tcb.ApcState.Process = tcb.Process;

	tcb.State = static_cast<unsigned char>(Initialized);

	tcb.Priority = p.system_thread ? system_thread_priority : user_thread_priority;
	tcb.BasePriority = tcb.Priority;
	tcb.PreviousMode = static_cast<char>(p.system_thread ? KernelMode : UserMode);
	tcb.SystemThread = p.system_thread ? 1 : 0;
	tcb.ApcQueueable = 1;
	tcb.EnableStackSwap = 1;

	et.Cid.UniqueProcess = ptr(p.process_id);
	et.Cid.UniqueThread = ptr(p.thread_id);

	// Windows keeps the two separately because of the stub; here both are the routine itself.
	et.StartAddress = ptr(p.start_addr);
	et.Win32StartAddress = ptr(p.start_addr);

	et.CreateTime.QuadPart = win_system_time();

	return et;
}


inline void set_thread_state(const emu_object<_ETHREAD>& et, const KTHREAD_STATE state, const bool running)
{
	const auto tcb = et.field(&_ETHREAD::Tcb);

	tcb.field(&_KTHREAD::State).write(static_cast<unsigned char>(state));
	tcb.field(&_KTHREAD::Running).write(static_cast<unsigned char>(running ? 1 : 0));
}

inline void set_thread_wait_reason(const emu_object<_ETHREAD>& et, const KWAIT_REASON reason)
{
	et.field(&_ETHREAD::Tcb).field(&_KTHREAD::WaitReason)
		.write(static_cast<unsigned char>(reason));
}

inline void set_thread_processor(const emu_object<_ETHREAD>& et, const std::uint32_t number)
{
	et.field(&_ETHREAD::Tcb).field(&_KTHREAD::NextProcessor).write(number);
}

inline void count_thread_switch(const emu_object<_ETHREAD>& et)
{
	auto switches = et.field(&_ETHREAD::Tcb).field(&_KTHREAD::ContextSwitches);
	switches.write(switches.read() + 1);
}

inline void set_thread_exit_time(const emu_object<_ETHREAD>& et, const std::int64_t time)
{
	et.field(&_ETHREAD::ExitTime).field(&_LARGE_INTEGER::QuadPart).write(time);
}
