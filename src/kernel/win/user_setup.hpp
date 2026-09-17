#pragma once
#include "../../emu/object.hpp"
#include "process_params.hpp"
#include "per_cpu.hpp"
#include "defs.hpp"
#include "../../target.hpp"
#include <algorithm>
#include <cstddef>
#include <string>

namespace win_target
{
#if defined(KERNEMUL_ARCH_ARM64)
	inline constexpr std::uint16_t image_machine          = 0xAA64; // ARM64
	inline constexpr std::uint16_t processor_architecture = 12;     // ARM64

	// ARM64 has no recursive self map to name, so nothing here reports one.
	inline constexpr addr_t pte_base = 0;

	// _CONTEXT calls the program counter something different on each arch, and a crash dump
	// repeats it outside the captured context, where the reader looks for it at a fixed offset.
	inline constexpr std::size_t context_pc_offset = offsetof(_CONTEXT, Pc);
#else
	inline constexpr std::uint16_t image_machine          = 0x8664; // AMD64
	inline constexpr std::uint16_t processor_architecture = 9;      // AMD64

	// MmPteBase: the pml4 slot that points at the pml4, as a virtual address. The slot itself
	// is x86::self_map_pml4_index, which is what the mmu actually writes.
	inline constexpr addr_t pte_base = 0xFFFFF08000000000;

	inline constexpr std::size_t context_pc_offset = offsetof(_CONTEXT, Rip);
#endif
}

constexpr std::uint64_t kuser_shared_data_user_va   = 0x7FFE0000;
constexpr std::uint64_t kuser_shared_data_kernel_va  = 0xFFFFF78000000000;

// How much physical memory the guest is told it has. The fake PFN database is sized from the
// same number, so a driver that walks 0..NumberOfPhysicalPages cannot walk off the end of it.
// Every page of that array is host memory the emulator commits up front -- the mmu backs a
// physical allocation with a std::vector, mapped into every vcpu -- which is why this is 1GB
// of 4K pages rather than the 4GB it used to claim.
inline constexpr std::uint64_t emulated_physical_pages = 0x40000;

// Only what an image whose NtBuildNumber cannot be read falls back to. The mapped ntoskrnl is
// the authority on its own build; see win_kernel_state::nt_build_number.
inline constexpr std::uint32_t default_build_number = 19045;

// The processor count reaches the guest in several unrelated places, which have to agree.
inline _KUSER_SHARED_DATA make_default_kuser_shared_data(const std::size_t processors)
{
	_KUSER_SHARED_DATA sd{};

	sd.NtMajorVersion = 10;
	sd.NtMinorVersion = 0;
	sd.NtBuildNumber = default_build_number;
	sd.NtProductType = NtProductWinNt;
	sd.ProductTypeIsValid = 1;
	sd.NativeProcessorArchitecture = win_target::processor_architecture;
	sd.ImageNumberLow = win_target::image_machine;
	sd.ImageNumberHigh = win_target::image_machine;
	sd.ActiveProcessorCount = static_cast<std::uint32_t>(processors);
	sd.ActiveGroupCount = 1;
	sd.NumberOfPhysicalPages = static_cast<std::uint32_t>(emulated_physical_pages);
	sd.LargePageMinimum = 0x200000;
	sd.TickCountMultiplier = default_tick_count_multiplier;

	const auto root_chars = std::min(windows_dir.size(), std::size(sd.NtSystemRoot) - 1);
	std::char_traits<char16_t>::copy(sd.NtSystemRoot, windows_dir.data(), root_chars);
	sd.NtSystemRoot[root_chars] = u'\0';

	return sd;
}

inline _PEB64 make_default_peb(const std::size_t processors,
	const std::uint32_t build = default_build_number)
{
	_PEB64 peb{};

	peb.NumberOfProcessors = static_cast<std::uint32_t>(processors);

	peb.HeapSegmentReserve = 0x100000;
	peb.HeapSegmentCommit = 0x1000;
	peb.HeapDeCommitTotalFreeThreshold = 0x10000;
	peb.HeapDeCommitFreeBlockThreshold = 0x1000;
	peb.MaximumNumberOfHeaps = 0x10;

	peb.OSMajorVersion = 10;
	peb.OSBuildNumber = build;
	peb.OSPlatformId = 2;

	peb.ImageSubsystem = 3;
	peb.ImageSubsystemMajorVersion = 6;

	return peb;
}

inline _TEB64 make_default_teb(addr_t teb_addr, addr_t stack_base,
	std::size_t stack_size, std::uint64_t process_id,
	std::uint32_t thread_id, addr_t peb_address, std::size_t processors)
{
	_TEB64 teb{};

	// RtlGetCurrentProcessorNumber takes a slow path when the bit is clear, so it is set.
	teb.PrimaryGroupAffinity.Mask = affinity_mask(processors);
	teb.PrimaryGroupAffinity.Group = 0;

	teb.NtTib.StackBase = stack_base + stack_size;
	teb.NtTib.StackLimit = stack_base;
	teb.NtTib.Self = teb_addr;
	teb.ClientId.UniqueProcess = process_id;
	teb.ClientId.UniqueThread = thread_id;
	teb.ProcessEnvironmentBlock = peb_address;

	return teb;
}
