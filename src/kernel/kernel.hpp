#pragma once
#include "../process/process.hpp"
#include "../emu/emu.hpp"

class os_emulator
{
public:
	explicit os_emulator(std::shared_ptr<emu> emu)
		: emu_(std::move(emu)) { }

	virtual ~os_emulator() = default;

	emu& emu() { return *emu_; }

protected:
	std::shared_ptr<struct emu> emu_;
};

struct win_kernel_state
{
	kernel_process sys_proc;
};

class windows_emulator : public os_emulator
{
public:
	using os_emulator::os_emulator;

	win_kernel_state& kernel() { return kernel_; }

private:
	win_kernel_state kernel_;
};
