#pragma once
#include "../../emu/object.hpp"
#include "types.hpp"

inline _PEB64 make_default_peb()
{
	_PEB64 peb{};

	peb.NumberOfProcessors = 1;

	peb.HeapSegmentReserve = 0x100000;
	peb.HeapSegmentCommit = 0x1000;
	peb.HeapDeCommitTotalFreeThreshold = 0x10000;
	peb.HeapDeCommitFreeBlockThreshold = 0x1000;
	peb.MaximumNumberOfHeaps = 0x10;

	// todo: fetch these automatically
	peb.OSMajorVersion = 10;
	peb.OSBuildNumber = 19045;
	peb.OSPlatformId = 2;

	peb.ImageSubsystem = 3;
	peb.ImageSubsystemMajorVersion = 6;

	return peb;
}

inline _TEB64 make_default_teb(addr_t teb_addr, addr_t stack_base,
	std::size_t stack_size, std::uint64_t process_id,
	std::uint32_t thread_id, addr_t peb_address)
{
	_TEB64 teb{};

	teb.NtTib.StackBase = stack_base + stack_size;
	teb.NtTib.StackLimit = stack_base;
	teb.NtTib.Self = teb_addr;
	teb.ClientId.UniqueProcess = process_id;
	teb.ClientId.UniqueThread = thread_id;
	teb.ProcessEnvironmentBlock = peb_address;

	return teb;
}
