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
