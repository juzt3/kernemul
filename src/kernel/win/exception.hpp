#pragma once
#include "../kernel.hpp"

class win_kernel_state;

namespace win {

struct win_exception final : os_exception
{
	explicit win_exception(win_kernel_state& kernel);
	bool handle(vcpu& cpu, cpu_exception ex) override;

private:
	win_kernel_state& kernel_;
};

} // namespace win
