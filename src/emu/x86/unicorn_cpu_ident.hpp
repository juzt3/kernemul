#pragma once
#include "../../target.hpp"

#if !defined(KERNEMUL_ARCH_ARM64)

class x86_unicorn_emu;

namespace x86
{

// Answers the CPUID leaves and msrs Unicorn either does not model or models as a cpu no shipped
// machine is. Unicorn-only: it needs rdmsr/wrmsr instruction hooks and a selectable cpu model,
// neither of which whp has. Called once, before any vcpu exists; the hooks own the state.
void install_cpu_identity(x86_unicorn_emu& emu);

}

#endif
