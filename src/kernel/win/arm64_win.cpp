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

	return cpu;
}
