#include "emu/unicorn.hpp"
#include "util/logs.hpp"

int main()
{
	auto arch = std::make_shared<x86_arch>();
	unicorn_emu emu(arch);

	auto cpu = emu.add_vcpu();

	emu.map_mem(0x1000, 0x1000, prot_all);
	emu.map_mem(0x2000, 0x1000, prot_rw);

	LOG("created unicorn x86 backend with {} vcpu", emu.cpus().size());
}
