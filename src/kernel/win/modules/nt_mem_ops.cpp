#include "nt_mem_ops.hpp"
#include "../win_kernel.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <vector>

namespace
{

// MmCopyMemory's flags. Exactly one says where the source address lives, and
// that is the whole of what they decide.
constexpr std::uint32_t mm_copy_memory_physical = 0x1;
constexpr std::uint32_t mm_copy_memory_virtual = 0x2;

}

// What a driver asks the memory manager about an address it is holding. The
// page tables the emulator's mmu walks are the guest's own, so these answer
// from the same tables the guest faults against rather than from a shadow of
// them.
void modules::register_ntoskrnl_mem_ops(win_kernel_state& state, proc_module& mod)
{
	state.redirect(mod, "MmIsAddressValid",
		[](vcpu& cpu, const addr_t virtual_address) -> bool
		{
			auto& space = *cpu.curr_addr_space();
			const bool valid = space.mmu_->virt_to_phys(space, virtual_address).has_value();

			THREAD_LOG_INFO("MmIsAddressValid(0x{:X}) -> {}", virtual_address, valid);

			return valid;
		});

	// Zero for an address that is not mapped, which is what the real one
	// returns and what a caller checks for -- there is no error path.
	state.redirect(mod, "MmGetPhysicalAddress",
		[](vcpu& cpu, const addr_t base_address) -> std::uint64_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto pa = space.mmu_->virt_to_phys(space, base_address).value_or(0);

			if (!pa)
				THREAD_LOG_WARN("MmGetPhysicalAddress: 0x{:X} is not mapped", base_address);
			else
				THREAD_LOG_INFO("MmGetPhysicalAddress(0x{:X}) -> 0x{:X}", base_address, pa);

			return pa;
		});

	// The reverse walk. Real NT reads it straight out of the PFN database, so
	// a page mapped twice has one answer there and this has whichever the
	// search reaches first -- which is the same answer whenever there is only
	// one mapping, and there is only ever one here.
	state.redirect(mod, "MmGetVirtualForPhysical",
		[](vcpu& cpu, const std::uint64_t physical_address) -> addr_t
		{
			auto& space = *cpu.curr_addr_space();
			const auto va = space.mmu_->phys_to_virt(space, physical_address).value_or(0);

			if (!va)
				THREAD_LOG_WARN("MmGetVirtualForPhysical: 0x{:X} is not mapped anywhere",
					physical_address);
			else
				THREAD_LOG_INFO("MmGetVirtualForPhysical(0x{:X}) -> 0x{:X}", physical_address, va);

			return va;
		});

	// MM_COPY_ADDRESS is a union of a virtual and a physical address, so the
	// source arrives as one eight-byte value and the flags say which it is.
	state.redirect(mod, "MmCopyMemory",
		[](vcpu& cpu, const addr_t target_address, const std::uint64_t source_address,
			const std::uint64_t number_of_bytes, const std::uint32_t flags,
			emu_object<std::uint64_t> number_of_bytes_transferred) -> NTSTATUS
		{
			const auto kind = flags & (mm_copy_memory_physical | mm_copy_memory_virtual);

			if (kind != mm_copy_memory_physical && kind != mm_copy_memory_virtual)
			{
				THREAD_LOG_WARN("MmCopyMemory: flags 0x{:X} name neither a virtual source nor a "
					"physical one", flags);
				return STATUS_INVALID_PARAMETER;
			}

			auto& space = *cpu.curr_addr_space();
			std::vector<std::uint8_t> buffer(number_of_bytes);

			// The point of MmCopyMemory is that a source it cannot reach is an
			// error rather than a bugcheck, so the fault the read throws is the
			// one thing here that is caught.
			try
			{
				if (kind == mm_copy_memory_physical)
					space.mmu_->read_phys(source_address, buffer.data(), number_of_bytes);
				else
					space.read_mem(source_address, buffer.data(), number_of_bytes);
			}
			catch (const std::exception& e)
			{
				THREAD_LOG_WARN("MmCopyMemory: cannot read {} bytes from {} 0x{:X}: {}",
					number_of_bytes, kind == mm_copy_memory_physical ? "physical" : "virtual",
					source_address, e.what());

				if (number_of_bytes_transferred)
					number_of_bytes_transferred.write(0);

				return STATUS_INVALID_ADDRESS;
			}

			space.write_mem(target_address, buffer.data(), number_of_bytes);

			if (number_of_bytes_transferred)
				number_of_bytes_transferred.write(number_of_bytes);

			THREAD_LOG_INFO("MmCopyMemory(target=0x{:X}, source=0x{:X}, {} bytes, flags=0x{:X})",
				target_address, source_address, number_of_bytes, flags);

			return STATUS_SUCCESS;
		});
}
