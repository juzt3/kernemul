#include "../../target.hpp"

#if !defined(KERNEMUL_ARCH_ARM64)

#include "x86_win.hpp"
#include "../../emu/x86/addr_space.hpp"

namespace ia32 {
#include <ia32.hpp>
}

// One pml4 slot pointing back at the table it sits in, so a walk that keeps choosing it stays on
// the page tables and the guest can read them as ordinary memory.
void x86_win_emulator::install_self_map(::addr_space& space)
{
	const auto* const x86_space = dynamic_cast<const x86::addr_space*>(&space);

	if (!x86_space || !x86_space->pml4_pa)
		return;

	ia32::pt_entry_64 entry{};
	entry.present = 1;
	entry.write = 1;
	entry.page_frame_number = x86_space->pml4_pa >> 12;

	space.mmu_->write_phys(
		x86_space->pml4_pa + self_map_pml4_index * sizeof(entry), entry);

	LOG_INFO("self map at pml4[0x{:X}] -> page table root 0x{:X}",
		self_map_pml4_index, x86_space->pml4_pa);
}

#endif
