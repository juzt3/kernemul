#pragma once
#include "../process/process.hpp"
#include "../emu/emu.hpp"
#include <map>
#include <mutex>

class os_emulator
{
public:
	explicit os_emulator(std::shared_ptr<emu> emu)
		: emu_(std::move(emu)) { }

	virtual ~os_emulator() = default;

	emu& emu() { return *emu_; }

protected:
	std::shared_ptr<class emu> emu_;
};

struct kernel_state
{
	virtual ~kernel_state() = default;

	virtual std::shared_ptr<process> create_user_process(std::string_view name) = 0;

	std::shared_ptr<process> find_process(process::id_type id)
	{
		std::lock_guard lock(proc_mtx_);
		const auto it = processes.find(id);
		return it != processes.end() ? it->second : nullptr;
	}

protected:
	std::mutex proc_mtx_;
	std::map<process::id_type, std::shared_ptr<process>> processes;
};

struct win_kernel_state : kernel_state
{
	static constexpr process::id_type sys_proc_id = 4;
	static constexpr process::id_type proc_id_step = 4;

	std::shared_ptr<kernel_process> sys_proc;

	win_kernel_state()
		:	sys_proc(std::make_shared<kernel_process>(sys_proc_id))
	{
		processes[sys_proc_id] = sys_proc;
	}

	std::shared_ptr<process> create_user_process(std::string_view name) override
	{
		std::lock_guard lock(proc_mtx_);
		const auto id = next_id_;
		auto proc = std::make_shared<user_process>(id);
		processes[id] = proc;
		next_id_ += proc_id_step;
		return proc;
	}

private:
	process::id_type next_id_ = 8;
};

class windows_emulator : public os_emulator
{
public:
	using os_emulator::os_emulator;

	win_kernel_state& kernel() { return kernel_; }

private:
	win_kernel_state kernel_;
};
