#pragma once

#include "../emulator/emulator.hpp"
#include "../emulator/object.hpp"
#include "kernel_def.hpp"
#include "process_loader.hpp"

#include <cstdint>
#include <memory>

struct alignas(16) xmm_state_register_t
{
	std::uint64_t low;
	std::uint64_t high;
};

struct thread_state_t
{
	std::uint64_t rax;
	std::uint64_t rbx;
	std::uint64_t rcx;
	std::uint64_t rdx;
	std::uint64_t rsi;
	std::uint64_t rdi;
	std::uint64_t rbp;
	std::uint64_t rsp;
	std::uint64_t r8;
	std::uint64_t r9;
	std::uint64_t r10;
	std::uint64_t r11;
	std::uint64_t r12;
	std::uint64_t r13;
	std::uint64_t r14;
	std::uint64_t r15;
	std::uint64_t rip;
	std::uint64_t rflags;

	xmm_state_register_t xmm0, xmm1, xmm2, xmm3;
	xmm_state_register_t xmm4, xmm5, xmm6, xmm7;
	xmm_state_register_t xmm8, xmm9, xmm10, xmm11;
	xmm_state_register_t xmm12, xmm13, xmm14, xmm15;
};

class thread_t
{
public:
	using time_point_type = std::chrono::steady_clock::time_point;
	using address_type = emulator_t::address_type;
	using size_type = emulator_t::size_type;
	using id_type = std::uint64_t;

	static constexpr size_type ms_to_expire = 300;

	explicit thread_t(const id_type id, std::shared_ptr<emulator_t> emulator, std::shared_ptr<process_t> process,
	                  emulator_object_t<_ETHREAD> object)
			:	id_(id),
				emulator_(std::move(emulator)),
				process_(std::move(process)),
				object_(std::move(object)) { }

	[[nodiscard]] id_type id() const
	{
		return id_;
	}

	[[nodiscard]] const std::shared_ptr<process_t>& process() const
	{
		return process_;
	}

	[[nodiscard]] address_type address() const
	{
		return object_.address();
	}

	[[nodiscard]] emulator_object_t<_ETHREAD>& object()
	{
		return object_;
	}

	[[nodiscard]] const emulator_object_t<_ETHREAD>& object() const
	{
		return object_;
	}

	[[nodiscard]] thread_state_t& state()
	{
		return state_;
	}

	[[nodiscard]] const thread_state_t& state() const
	{
		return state_;
	}

	void start();
	void stop();

	[[nodiscard]] bool is_expired() const;

	void save_state();
	void load_state();

protected:
	[[nodiscard]] static time_point_type time_point_now()
	{
		return std::chrono::steady_clock::now();
	}

	id_type id_;
	std::shared_ptr<emulator_t> emulator_;
	std::shared_ptr<process_t> process_;
	emulator_object_t<_ETHREAD> object_;

	time_point_type last_time_ran_ = { };
	thread_state_t state_ = { };
};

namespace kernel
{
	[[nodiscard]] std::shared_ptr<thread_t> create_thread(const std::shared_ptr<emulator_t>& emulator,
		thread_t::id_type thread_id, const std::shared_ptr<process_t>& process);

	void switch_thread();
}
