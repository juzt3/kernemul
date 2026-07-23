#pragma once

#include "../emulator/emulator.hpp"

#include <cstdint>
#include <cstddef>
#include <memory>

// Guest memory layout for the x64 Windows PEB (Process Environment Block).
// All pointer fields are stored as std::uint64_t since they represent guest virtual addresses.
// Shared between kernel-side process setup and usermode process setup.
struct peb64_t
{
	std::uint8_t InheritedAddressSpace;               // 0x00
	std::uint8_t ReadImageFileExecOptions;            // 0x01
	std::uint8_t BeingDebugged;                       // 0x02
	std::uint8_t BitField;                            // 0x03
	std::uint8_t Padding0[4];                         // 0x04
	std::uint64_t Mutant;                             // 0x08
	std::uint64_t ImageBaseAddress;                   // 0x10
	std::uint64_t Ldr;                                // 0x18
	std::uint64_t ProcessParameters;                  // 0x20
	std::uint64_t SubSystemData;                      // 0x28
	std::uint64_t ProcessHeap;                        // 0x30
	std::uint64_t FastPebLock;                        // 0x38
	std::uint64_t AtlThunkSListPtr;                   // 0x40
	std::uint64_t IFEOKey;                            // 0x48
	std::uint32_t CrossProcessFlags;                  // 0x50
	std::uint8_t Padding1[4];                         // 0x54
	std::uint64_t KernelCallbackTable;                // 0x58
	std::uint32_t SystemReserved;                     // 0x60
	std::uint32_t AtlThunkSListPtr32;                 // 0x64
	std::uint64_t ApiSetMap;                          // 0x68
	std::uint32_t TlsExpansionCounter;                // 0x70
	std::uint8_t Padding2[4];                         // 0x74
	std::uint64_t TlsBitmap;                          // 0x78
	std::uint32_t TlsBitmapBits[2];                   // 0x80
	std::uint64_t ReadOnlySharedMemoryBase;           // 0x88
	std::uint64_t SharedData;                         // 0x90
	std::uint64_t ReadOnlyStaticServerData;           // 0x98
	std::uint64_t AnsiCodePageData;                   // 0xA0
	std::uint64_t OemCodePageData;                    // 0xA8
	std::uint64_t UnicodeCaseTableData;               // 0xB0
	std::uint32_t NumberOfProcessors;                 // 0xB8
	std::uint32_t NtGlobalFlag;                       // 0xBC
	std::uint64_t CriticalSectionTimeout;             // 0xC0
	std::uint64_t HeapSegmentReserve;                 // 0xC8
	std::uint64_t HeapSegmentCommit;                  // 0xD0
	std::uint64_t HeapDeCommitTotalFreeThreshold;     // 0xD8
	std::uint64_t HeapDeCommitFreeBlockThreshold;     // 0xE0
	std::uint32_t NumberOfHeaps;                      // 0xE8
	std::uint32_t MaximumNumberOfHeaps;               // 0xEC
	std::uint64_t ProcessHeaps;                       // 0xF0
	std::uint64_t GdiSharedHandleTable;               // 0xF8
	std::uint64_t ProcessStarterHelper;               // 0x100
	std::uint32_t GdiDCAttributeList;                 // 0x108
	std::uint8_t Padding3[4];                         // 0x10C
	std::uint64_t LoaderLock;                         // 0x110
	std::uint32_t OSMajorVersion;                     // 0x118
	std::uint32_t OSMinorVersion;                     // 0x11C
	std::uint16_t OSBuildNumber;                      // 0x120
	std::uint16_t OSCSDVersion;                       // 0x122
	std::uint32_t OSPlatformId;                       // 0x124
	std::uint32_t ImageSubsystem;                     // 0x128
	std::uint32_t ImageSubsystemMajorVersion;         // 0x12C
	std::uint32_t ImageSubsystemMinorVersion;         // 0x130
};

static_assert(offsetof(peb64_t, BeingDebugged) == 0x02);
static_assert(offsetof(peb64_t, ImageBaseAddress) == 0x10);
static_assert(offsetof(peb64_t, Ldr) == 0x18);
static_assert(offsetof(peb64_t, ProcessParameters) == 0x20);
static_assert(offsetof(peb64_t, ProcessHeap) == 0x30);
static_assert(offsetof(peb64_t, ApiSetMap) == 0x68);
static_assert(offsetof(peb64_t, AnsiCodePageData) == 0xA0);
static_assert(offsetof(peb64_t, OemCodePageData) == 0xA8);
static_assert(offsetof(peb64_t, UnicodeCaseTableData) == 0xB0);
static_assert(offsetof(peb64_t, NumberOfProcessors) == 0xB8);
static_assert(offsetof(peb64_t, NtGlobalFlag) == 0xBC);
static_assert(offsetof(peb64_t, HeapSegmentReserve) == 0xC8);
static_assert(offsetof(peb64_t, HeapSegmentCommit) == 0xD0);
static_assert(offsetof(peb64_t, HeapDeCommitTotalFreeThreshold) == 0xD8);
static_assert(offsetof(peb64_t, HeapDeCommitFreeBlockThreshold) == 0xE0);
static_assert(offsetof(peb64_t, NumberOfHeaps) == 0xE8);
static_assert(offsetof(peb64_t, MaximumNumberOfHeaps) == 0xEC);
static_assert(offsetof(peb64_t, ProcessHeaps) == 0xF0);
static_assert(offsetof(peb64_t, GdiSharedHandleTable) == 0xF8);
static_assert(offsetof(peb64_t, OSMajorVersion) == 0x118);
static_assert(offsetof(peb64_t, OSMinorVersion) == 0x11C);
static_assert(offsetof(peb64_t, OSBuildNumber) == 0x120);
static_assert(offsetof(peb64_t, OSPlatformId) == 0x124);
static_assert(offsetof(peb64_t, ImageSubsystem) == 0x128);
static_assert(offsetof(peb64_t, ImageSubsystemMajorVersion) == 0x12C);
static_assert(offsetof(peb64_t, ImageSubsystemMinorVersion) == 0x130);

constexpr std::size_t peb64_alloc_size = 0x800;

namespace kernel
{
	// Optional process-specific pointers layered on top of the common PEB fields.
	// A zeroed options struct produces a minimal PEB suitable for kernel-only processes.
	struct peb_setup_options_t
	{
		emulator_t::address_type image_base_address = 0;
		emulator_t::address_type ldr = 0;
		emulator_t::address_type process_parameters = 0;
		emulator_t::address_type api_set_map = 0;
		emulator_t::address_type gdi_shared_handle_table = 0;
	};

	// Populate a peb64_t at the given pre-allocated guest address. Fills common fields
	// (OS version, processor count, heap sizing, subsystem) plus any pointers set in options.
	void write_process_peb(const std::shared_ptr<emulator_t>& emulator,
		emulator_t::address_type peb_address,
		const peb_setup_options_t& options = {});
}
