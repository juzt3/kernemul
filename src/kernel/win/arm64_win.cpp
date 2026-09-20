#include "../../target.hpp"
#if defined(KERNEMUL_ARCH_ARM64)
#include "arm64_win.hpp"
#include "../process.hpp"
#include "../../emu/mmu.hpp"

std::shared_ptr<vcpu> arm64_win_emulator::add_vcpu()
{
	auto cpu = emu_->add_vcpu();
	auto space = cpu->curr_addr_space();

	// Sixteen 128-byte entries, 2KB aligned; nothing is written into it, so VBAR_EL1 reads sane.
	constexpr std::size_t vector_table_size = 0x800;
	const addr_t vbar = space->alloc(vector_table_size, prot_rx | prot_supervisor);
	cpu->reg(arm64::vbar_el1, vbar);

	const auto& pcpu = kernel().init_per_cpu(*cpu);
	set_pcr(*cpu, pcpu.address());

	// Where usermode reads the processor number, TPIDRRO_EL0: low byte processor, next group.
	constexpr std::uint64_t processor_group = 0;
	cpu->reg(arm64::tpidrro_el0, (processor_group << 8) | cpu->id());

	return cpu;
}

#endif // KERNEMUL_ARCH_ARM64
