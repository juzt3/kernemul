#include "thread.hpp"
#include "kernel.hpp"
#include "../emulator/object.hpp"

#include "../util/logs.hpp"

#include <format>

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

	GLOBAL_LOG("created thread (thread id={}, process id={}, object address=0x{:X})",
		thread_id, process->id(), thread->address());

	return thread;
}

void kernel::switch_thread(const std::shared_ptr<emulator_t>& emulator, const bool delete_current, const bool force)
{
	GLOBAL_LOG("switch_thread called (delete_current={}, force={}, current_thread_id={}, pending_threads={})",
		delete_current, force,
		current_thread ? current_thread->id() : 0,
		pending_threads.size());

	if (pending_thread_switch || pending_threads.empty() || (!delete_current && !force && !current_thread->is_expired()))
	{
		return;
	}

	const auto queue_size = pending_threads.size();
	bool found_runnable = false;

	for (std::size_t i = 0; i < queue_size; ++i)
	{
		if (!pending_threads.front()->is_sleeping())
		{
			found_runnable = true;
			break;
		}

		auto sleeping_thread = pending_threads.front();
		pending_threads.pop();
		pending_threads.push(std::move(sleeping_thread));
	}

	if (!found_runnable)
	{
		return;
	}

	const emulator_err_t error = emulator->stop();

	error.throw_if("stop thread");

	if (delete_current)
	{
		delete_current_thread = true;
	}

	pending_thread_switch = true;

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

void thread_t::start()
{
	update_last_time_ran();

	load_state();

	const auto rip = emulator_->read_register<x86::reg::rip, emulator_t::address_type>();

	(void)emulator_->run_at(rip, emulator_t::thread_return_address);
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
	emulator_->write_register<x86::reg::rflags>(state_.rflags);

#define LOAD_XMM(n) emulator_->write_register<x86::reg::xmm##n>(state_.xmm##n)

	LOAD_XMM(0);  LOAD_XMM(1);  LOAD_XMM(2);  LOAD_XMM(3);
	LOAD_XMM(4);  LOAD_XMM(5);  LOAD_XMM(6);  LOAD_XMM(7);
	LOAD_XMM(8);  LOAD_XMM(9);  LOAD_XMM(10); LOAD_XMM(11);
	LOAD_XMM(12); LOAD_XMM(13); LOAD_XMM(14); LOAD_XMM(15);
}
