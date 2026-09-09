#pragma once
#include "process.hpp"
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

	virtual std::shared_ptr<process> create_process(std::string_view name) = 0;

	std::shared_ptr<process> find_process(const process::id_type id)
	{
		std::scoped_lock lock(proc_mtx_);
		const auto it = processes.find(id);
		return it != processes.end() ? it->second : nullptr;
	}

protected:
	std::mutex proc_mtx_;
	std::map<process::id_type, std::shared_ptr<process>> processes;
};
