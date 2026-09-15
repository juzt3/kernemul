#include "../../target.hpp"
#if defined(KERNEMUL_ARCH_ARM64)
#include "arm64_win.hpp"
#include "../process.hpp"
#include "../../emu/mmu.hpp"

std::shared_ptr<vcpu> arm64_win_emulator::add_vcpu()
{
	auto cpu = emu_->add_vcpu();
	auto space = cpu->curr_addr_space();

	// The AArch64 vector table is sixteen 128-byte entries and must be 2KB
	// aligned. Nothing is written into it: Unicorn calls the interrupt hook in
	// place of arm_cpu_do_interrupt, so control never reaches these vectors --
	// win_exception::handle sees the fault first. It is installed for the same
	// reason init_idt is on x86, so guest code that reads VBAR_EL1 sees
	// something sane.
	constexpr std::size_t vector_table_size = 0x800;
	const addr_t vbar = space->alloc(vector_table_size, prot_rx | prot_supervisor);
	cpu->reg(arm64::vbar_el1, vbar);

	// TPIDR_EL1 is not part of a thread's context, so unlike the GS base on
	// x86-64 it stays pointed at this cpu's block for as long as the cpu lives.
	const auto& pcpu = kernel().init_per_cpu(*cpu);
	set_pcr(*cpu, pcpu.address());

	// Where usermode looks for the processor number: RtlGetCurrentProcessorNumber
	// is an mrs of TPIDRRO_EL0 and nothing else. Low byte the processor, next
	// the group. Per cpu rather than per thread, like TPIDR_EL1.
	constexpr std::uint64_t processor_group = 0;
	cpu->reg(arm64::tpidrro_el0, (processor_group << 8) | cpu->id());

	return cpu;
}

#endif // KERNEMUL_ARCH_ARM64
