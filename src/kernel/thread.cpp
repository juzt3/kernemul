#include "thread.hpp"
#include "kernel.hpp"
#include "segments.hpp"
#include "../emulator/object.hpp"
#include "../user/user_defs.hpp"

#include "../util/logs.hpp"

#include <format>
#include <span>
#include <thread>

std::shared_ptr<thread_t> kernel::create_thread(const std::shared_ptr<emulator_t>& emulator,
	const thread_t::id_type thread_id, const std::shared_ptr<process_t>& process)
{
	const auto name = std::format("ETHREAD_{}", thread_id);

	_ETHREAD contents = { };

	contents.Tcb.ApcState.Process = contents.Tcb.Process = reinterpret_cast<_KPROCESS*>(process->address());
	contents.Cid.UniqueProcess = reinterpret_cast<HANDLE>(process->id());
	contents.Cid.UniqueThread = reinterpret_cast<HANDLE>(thread_id);

	auto object = emulator_object_t<_ETHREAD>::allocate(emulator, contents, name);

	auto thread = std::make_shared<thread_t>(thread_id, emulator, process, std::move(object));

	object_manager->register_object(thread->address(), std::make_shared<thread_object_t>(thread));

	GLOBAL_LOG("created thread (thread id={}, process id={}, object address=0x{:X})",
		thread_id, process->id(), thread->address());

	return thread;
}

void kernel::switch_thread(const std::shared_ptr<emulator_t>& emulator, const bool delete_current, const bool force)
{
	if (pending_thread_switch ||
		(!force && (pending_threads.empty() || (!delete_current && !current_thread->is_expired()))))
	{
		return;
	}

	if (delete_current)
	{
		delete_current_thread = true;
	}

	// set flag before stop - stop() is asynchronous (WHvCancelRunVirtualProcessor),
	// so the main thread can observe the cancellation and check this flag before we
	// get a chance to set it, causing the run loop to exit prematurely
	pending_thread_switch = true;

	const emulator_err_t error = emulator->stop();

	error.throw_if("stop thread");

	GLOBAL_LOG("switch_thread succeeded");
}

void thread_t::update_last_time_ran()
{
	last_time_ran_ = time_point_now();
}

void thread_t::sleep_for(const std::chrono::milliseconds duration)
{
	sleep_until_ = time_point_now() + duration;
}

bool thread_t::is_sleeping() const
{
	return sleep_until_ > time_point_now();
}

thread_t::time_point_type thread_t::sleep_until() const
{
	return sleep_until_;
}

bool thread_t::start()
{
	update_last_time_ran();

	load_state();

	const auto rip = emulator_->read_register<x86::reg::rip, emulator_t::address_type>();

	return static_cast<bool>(emulator_->run_at(rip, emulator_t::thread_return_address)) == false;
}

void thread_t::stop()
{
	const emulator_err_t error = emulator_->stop();

	error.throw_if("stop thread");

	save_state();
}

bool thread_t::is_expired() const
{
	const auto duration = time_point_now() - last_time_ran_;

	return std::chrono::milliseconds(ms_to_expire) <= duration;
}

void thread_t::save_state()
{
	state_.rax = emulator_->read_register<x86::reg::rax, std::uint64_t>();
	state_.rbx = emulator_->read_register<x86::reg::rbx, std::uint64_t>();
	state_.rcx = emulator_->read_register<x86::reg::rcx, std::uint64_t>();
	state_.rdx = emulator_->read_register<x86::reg::rdx, std::uint64_t>();
	state_.rsi = emulator_->read_register<x86::reg::rsi, std::uint64_t>();
	state_.rdi = emulator_->read_register<x86::reg::rdi, std::uint64_t>();
	state_.rbp = emulator_->read_register<x86::reg::rbp, std::uint64_t>();
	state_.rsp = emulator_->read_register<x86::reg::rsp, std::uint64_t>();
	state_.r8 = emulator_->read_register<x86::reg::r8, std::uint64_t>();
	state_.r9 = emulator_->read_register<x86::reg::r9, std::uint64_t>();
	state_.r10 = emulator_->read_register<x86::reg::r10, std::uint64_t>();
	state_.r11 = emulator_->read_register<x86::reg::r11, std::uint64_t>();
	state_.r12 = emulator_->read_register<x86::reg::r12, std::uint64_t>();
	state_.r13 = emulator_->read_register<x86::reg::r13, std::uint64_t>();
	state_.r14 = emulator_->read_register<x86::reg::r14, std::uint64_t>();
	state_.r15 = emulator_->read_register<x86::reg::r15, std::uint64_t>();
	state_.rip = emulator_->read_register<x86::reg::rip, std::uint64_t>();
	state_.rflags = emulator_->read_register<x86::reg::rflags, std::uint64_t>();

#define SAVE_XMM(n) state_.xmm##n = emulator_->read_register<x86::reg::xmm##n, xmm_state_register_t>()

	SAVE_XMM(0);  SAVE_XMM(1);  SAVE_XMM(2);  SAVE_XMM(3);
	SAVE_XMM(4);  SAVE_XMM(5);  SAVE_XMM(6);  SAVE_XMM(7);
	SAVE_XMM(8);  SAVE_XMM(9);  SAVE_XMM(10); SAVE_XMM(11);
	SAVE_XMM(12); SAVE_XMM(13); SAVE_XMM(14); SAVE_XMM(15);
}

void thread_t::load_state()
{
	emulator_->write_register<x86::reg::rax>(state_.rax);
	emulator_->write_register<x86::reg::rbx>(state_.rbx);
	emulator_->write_register<x86::reg::rcx>(state_.rcx);
	emulator_->write_register<x86::reg::rdx>(state_.rdx);
	emulator_->write_register<x86::reg::rsi>(state_.rsi);
	emulator_->write_register<x86::reg::rdi>(state_.rdi);
	emulator_->write_register<x86::reg::rbp>(state_.rbp);
	emulator_->write_register<x86::reg::rsp>(state_.rsp);
	emulator_->write_register<x86::reg::r8>(state_.r8);
	emulator_->write_register<x86::reg::r9>(state_.r9);
	emulator_->write_register<x86::reg::r10>(state_.r10);
	emulator_->write_register<x86::reg::r11>(state_.r11);
	emulator_->write_register<x86::reg::r12>(state_.r12);
	emulator_->write_register<x86::reg::r13>(state_.r13);
	emulator_->write_register<x86::reg::r14>(state_.r14);
	emulator_->write_register<x86::reg::r15>(state_.r15);

	emulator_->write_register<x86::reg::rip>(state_.rip);

	// clear TF - if the driver set trap flag before a context switch, absorb it
	// to prevent spurious INT1 after resuming
	emulator_->write_register<x86::reg::rflags>(state_.rflags & ~static_cast<std::uint64_t>(0x100));

#define LOAD_XMM(n) emulator_->write_register<x86::reg::xmm##n>(state_.xmm##n)

	LOAD_XMM(0);  LOAD_XMM(1);  LOAD_XMM(2);  LOAD_XMM(3);
	LOAD_XMM(4);  LOAD_XMM(5);  LOAD_XMM(6);  LOAD_XMM(7);
	LOAD_XMM(8);  LOAD_XMM(9);  LOAD_XMM(10); LOAD_XMM(11);
	LOAD_XMM(12); LOAD_XMM(13); LOAD_XMM(14); LOAD_XMM(15);

	if (state_.is_usermode)
	{
		kernel::swap_to_usermode_segments(emulator_);

		if (state_.gs_base != 0)
		{
			kernel::swap_to_usermode_gs(emulator_, state_.gs_base);
		}
	}
	else
	{
		kernel::swap_to_kernel_segments(emulator_);

		if (state_.gs_base != 0)
		{
			kernel::swap_to_kernel_gs(emulator_);
		}
	}
}

static bool find_next_runnable_thread()
{
	const auto queue_size = kernel::pending_threads.size();

	for (std::size_t i = 0; i < queue_size; ++i)
	{
		if (!kernel::pending_threads.front()->is_sleeping())
		{
			return true;
		}

		auto sleeping = kernel::pending_threads.front();
		kernel::pending_threads.pop();
		kernel::pending_threads.push(std::move(sleeping));
	}

	return false;
}

static bool wait_for_runnable_thread()
{
	while (true)
	{
		if (kernel::pending_threads.empty() && kernel::delete_current_thread)
		{
			return false;
		}

		if (find_next_runnable_thread())
		{
			return false;
		}

		// all queued threads are asleep - if current thread is still runnable, just re-enter it
		if (!kernel::delete_current_thread && !kernel::current_thread->is_sleeping())
		{
			GLOBAL_LOG("all queued threads sleeping, re-entering current thread {}", kernel::current_thread->id());
			return true;
		}

		// all threads asleep - sleep host until the earliest one wakes
		auto earliest = thread_t::time_point_type::max();

		// include current thread's wake time if it's sleeping and not being deleted
		if (!kernel::delete_current_thread && kernel::current_thread->is_sleeping())
		{
			earliest = kernel::current_thread->sleep_until();
		}

		auto temp_queue = kernel::pending_threads;
		while (!temp_queue.empty())
		{
			const auto& t = temp_queue.front();
			if (t->sleep_until() < earliest)
			{
				earliest = t->sleep_until();
			}
			temp_queue.pop();
		}

		const auto now = std::chrono::steady_clock::now();

		if (earliest > now)
		{
			GLOBAL_LOG("all threads sleeping, host sleeping for {}ms",
				std::chrono::duration_cast<std::chrono::milliseconds>(earliest - now).count());
			std::this_thread::sleep_until(earliest);
		}
	}
}

static void perform_thread_switch()
{
	const auto next_thread = kernel::pending_threads.front();
	kernel::pending_threads.pop();

	if (!kernel::delete_current_thread)
	{
		kernel::pending_threads.push(kernel::current_thread);
	}

	kernel::current_thread = next_thread;
	kernel::delete_current_thread = false;
}

void kernel::run_all_threads(const std::shared_ptr<emulator_t>& emulator, const emulator_t::address_type entry_point_address,
	std::function<void(const std::shared_ptr<thread_t>&)> on_thread_done)
{
	std::atomic_bool ended = false;

	auto thread_scheduler = std::thread(
		[&ended, emulator]()
		{
			try
			{
				while (!ended)
				{
					if (!pending_thread_switch)
					{
						switch_thread(emulator);
					}

					std::this_thread::sleep_for(std::chrono::milliseconds(15));
				}
			}
			catch (const std::exception& e)
			{
				GLOBAL_ERR_LOG("scheduler thread exception: {}", e.what());
			}
		}
	);

	emulator->write_register<x86::reg::rip>(entry_point_address);

	current_thread->save_state();

	std::shared_ptr<thread_t> last_thread;

	try
	{
		do
		{
			if (pending_thread_switch)
			{
				if (!wait_for_runnable_thread())
				{
					if (pending_threads.empty() && delete_current_thread)
					{
						break;
					}

					GLOBAL_LOG("switching thread {} -> {}", current_thread->id(), pending_threads.front()->id());
					perform_thread_switch();

					if (current_thread)
					{
						const auto thread_addr = current_thread->address();

						if (kprcb_address)
						{
							static_cast<void>(emulator->write_virtual_memory(
								kprcb_address + offsetof(_KPRCB, CurrentThread),
								&thread_addr, sizeof(thread_addr)));
						}

						if (kpcr_address)
						{
							constexpr std::uint64_t embedded_current_thread_offset = 0x188;
							static_cast<void>(emulator->write_virtual_memory(
								kpcr_address + embedded_current_thread_offset,
								&thread_addr, sizeof(thread_addr)));
						}
					}
				}
			}

			GLOBAL_LOG("running thread {}", current_thread->id());

			if (last_thread)
			{
				last_thread->save_state();
			}

			last_thread = current_thread;

			pending_thread_switch = false;

			if (const bool thread_finished = current_thread->start())
			{
				const auto rax = emulator->read_register<x86::reg::rax, std::uint64_t>();
				THREAD_LOG("thread returned to default return address and is now finished (rax=0x{:X})", rax);

				current_thread->save_state();

				// signal the thread's KTHREAD dispatcher header so waiters wake up
				constexpr std::int32_t signaled = 1;
				static_cast<void>(emulator->write_virtual_memory(
					current_thread->address() + offsetof(_KTHREAD, Header.SignalState),
					&signaled, sizeof(signaled)));

				if (on_thread_done)
				{
					on_thread_done(current_thread);
				}

				delete_current_thread = true;
				pending_thread_switch = true;
			}

		} while (pending_thread_switch);

		GLOBAL_LOG("run_all_threads finished (pending_threads={})", pending_threads.size());
	}
	catch (const std::exception& e)
	{
		GLOBAL_ERR_LOG("run_all_threads exception: {}", e.what());
	}

	ended = true;

	thread_scheduler.join();
}

std::shared_ptr<thread_t> kernel::create_thread_at(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type target_address, const std::span<const std::uint64_t> arguments,
	const emulator_t::address_type stack_base, const emulator_t::address_type teb_address)
{
	const auto thread_id = object_manager->allocate_id();
	const auto& process = process_entries.front();
	auto thread = create_thread(emulator, thread_id, process);

	emulator_t::address_type stack_top;

	if (stack_base != 0)
	{
		stack_top = stack_base - 0x1000;
	}
	else
	{
		constexpr emulator_t::size_type stack_size = 0x10000;
		const auto stack_allocation = emulator->heap_allocate(stack_size, prot_read_write, true);
		stack_allocation.error_or({}).throw_if("create_thread_at: allocate stack");
		stack_top = *stack_allocation + stack_size - 0x1000;
	}

	const emulator_t::address_type sentinel = emulator_t::thread_return_address;
	const emulator_t::address_type rsp = (stack_top & ~0xFull) - 8;

	emulator->write_virtual_memory(rsp, &sentinel, sizeof(sentinel))
		.throw_if("create_thread_at: write sentinel");

	thread->state().rip = target_address;
	thread->state().rsp = rsp;
	thread->state().rflags = 0x202;

	emulator->write_virtual_memory(thread->address() + offsetof(_ETHREAD, StartAddress), &target_address, sizeof(target_address))
		.throw_if("create_thread_at: write StartAddress");
	emulator->write_virtual_memory(thread->address() + offsetof(_ETHREAD, Win32StartAddress), &target_address, sizeof(target_address))
		.throw_if("create_thread_at: write Win32StartAddress");

	if (arguments.size() > 0)
	{
		thread->state().rcx = arguments[0];
	}

	if (arguments.size() > 1)
	{
		thread->state().rdx = arguments[1];
	}

	if (arguments.size() > 2)
	{
		thread->state().r8 = arguments[2];
	}

	if (arguments.size() > 3)
	{
		thread->state().r9 = arguments[3];
	}

	for (std::size_t i = 4; i < arguments.size(); ++i)
	{
		const emulator_t::address_type slot_address = rsp + 0x28 + (i - 4) * sizeof(std::uint64_t);
		emulator->write_virtual_memory(slot_address, &arguments[i], sizeof(std::uint64_t))
			.throw_if("create_thread_at: write stack argument");
	}

	if (teb_address != 0)
	{
		auto& state = thread->state();
		state.cs_selector = user_cs_selector;
		state.ss_selector = user_ds_selector;
		state.gs_base = teb_address;
		state.is_usermode = true;

		static_cast<void>(emulator->write_virtual_memory(
			teb_address + offsetof(user::teb64_t, ClientId.UniqueThread),
			&thread_id, sizeof(thread_id)));
	}

	GLOBAL_LOG("create_thread_at (tid={}, target=0x{:X}, args={}, usermode={})",
		thread_id, target_address, arguments.size(), teb_address != 0);

	return thread;
}

std::uint64_t kernel::run_thread_immediately(const std::shared_ptr<emulator_t>& emulator,
	const std::shared_ptr<thread_t>& thread)
{
	current_thread = thread;
	pending_thread_switch = false;
	delete_current_thread = false;

	GLOBAL_LOG("run_thread_immediately (tid={}, rip=0x{:X})", thread->id(), thread->state().rip);

	run_all_threads(emulator, thread->state().rip);

	return thread->state().rax;
}
