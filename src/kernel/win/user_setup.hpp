#pragma once
#include "../../emu/object.hpp"
#include "process_params.hpp"
#include "../../target.hpp"
#include <algorithm>
#include <string>

namespace win_target
{
#if defined(KERNEMUL_ARCH_ARM64)
	inline constexpr std::uint16_t image_machine          = 0xAA64; // ARM64
	inline constexpr std::uint16_t processor_architecture = 12;     // ARM64
#else
	inline constexpr std::uint16_t image_machine          = 0x8664; // AMD64
	inline constexpr std::uint16_t processor_architecture = 9;      // AMD64
#endif
}

constexpr std::uint64_t kuser_shared_data_user_va   = 0x7FFE0000;
constexpr std::uint64_t kuser_shared_data_kernel_va  = 0xFFFFF78000000000;

// The processor count reaches the guest in several unrelated places, which have to agree.
inline _KUSER_SHARED_DATA make_default_kuser_shared_data(const std::size_t processors)
{
	_KUSER_SHARED_DATA sd{};

	sd.NtMajorVersion = 10;
	sd.NtMinorVersion = 0;
	sd.NtBuildNumber = 19045;
	sd.NtProductType = NtProductWinNt;
	sd.ProductTypeIsValid = 1;
	sd.NativeProcessorArchitecture = win_target::processor_architecture;
	sd.ImageNumberLow = win_target::image_machine;
	sd.ImageNumberHigh = win_target::image_machine;
	sd.ActiveProcessorCount = static_cast<std::uint32_t>(processors);
	sd.ActiveGroupCount = 1;
	sd.NumberOfPhysicalPages = 0x100000;
	sd.LargePageMinimum = 0x200000;
	sd.TickCountMultiplier = 0x0FA00000;

	const auto root_chars = std::min(windows_dir.size(), std::size(sd.NtSystemRoot) - 1);
	std::char_traits<char16_t>::copy(sd.NtSystemRoot, windows_dir.data(), root_chars);
	sd.NtSystemRoot[root_chars] = u'\0';

	return sd;
}

inline _PEB64 make_default_peb(const std::size_t processors)
{
	_PEB64 peb{};

	peb.NumberOfProcessors = static_cast<std::uint32_t>(processors);

	peb.HeapSegmentReserve = 0x100000;
	peb.HeapSegmentCommit = 0x1000;
	peb.HeapDeCommitTotalFreeThreshold = 0x10000;
	peb.HeapDeCommitFreeBlockThreshold = 0x1000;
	peb.MaximumNumberOfHeaps = 0x10;

	peb.OSMajorVersion = 10;
	peb.OSBuildNumber = 19045;
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
	teb.PrimaryGroupAffinity.Mask = processors >= 64 ? ~0ull : (1ull << processors) - 1;
	teb.PrimaryGroupAffinity.Group = 0;

	teb.NtTib.StackBase = stack_base + stack_size;
	teb.NtTib.StackLimit = stack_base;
	teb.NtTib.Self = teb_addr;
	teb.ClientId.UniqueProcess = process_id;
	teb.ClientId.UniqueThread = thread_id;
	teb.ProcessEnvironmentBlock = peb_address;

	return teb;
}
