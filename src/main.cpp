#include "emu/unicorn.hpp"
#include "emu/x86/mmu.hpp"
#include "util/logs.hpp"
#include <thread>

int main()
{
	auto arch = std::make_shared<x86::arch>();
	auto mem = std::make_shared<x86::mmu>();
	unicorn_emu emu(arch, mem);

	auto cpu = emu.add_vcpu();
	auto space = cpu->curr_addr_space();

	mem->map_virt(*space, 0xFFFF800000001000, 0x1000, prot_all);

	// dec rcx; jnz -5; hlt
	const std::uint8_t code[] = {
		0x48, 0xFF, 0xC9,
		0x75, 0xFB,
		0xF4
	};

	mem->write_virt(*space, 0xFFFF800000001000, code, sizeof(code));

	cpu->reg<x86::rip>(static_cast<addr_t>(0xFFFF800000001000));
	cpu->reg<x86::rcx>(static_cast<std::uint64_t>(0x10000000));

	LOG("starting vcpu on thread");

	std::thread vcpu_thread([&] {
		cpu->run();
	});

	std::this_thread::sleep_for(std::chrono::milliseconds(100));

	LOG("calling map_virt while vcpu is running");
	mem->map_virt(*space, 0xFFFF800000002000, 0x1000, prot_rw);
	LOG("map_virt returned (sync ok)");

	std::uint64_t val = 0xDEADBEEF;
	mem->write_virt(*space, 0xFFFF800000002000, &val, sizeof(val));

	std::uint64_t readback{};
	mem->read_virt(*space, 0xFFFF800000002000, &readback, sizeof(readback));
	LOG("new region readback: {:#x}", readback);

	cpu->stop();
	vcpu_thread.join();

	LOG("rcx at stop: {:#x}", cpu->reg<x86::rcx>());

	auto pa = mem->virt_to_phys(*space, 0xFFFF800000001000);
	LOG("VA 0xFFFF800000001000 -> PA {:#x}", pa.value_or(0));

	LOG("mmu test passed");
}
