#pragma once
// Names the backend without naming its headers. unicorn's platform.h includes <windows.h> for
// its own usleep, and the SDK's ULONG and EXCEPTION_DISPOSITION are not the ones pdbex wrote
// into types_<arch>.hpp -- a translation unit cannot hold both. Everything that wants the guest
// types, main.cpp among them, goes through here instead.

#include "emu.hpp"

#include <cstddef>
#include <memory>

std::shared_ptr<emu> make_guest_emu(std::shared_ptr<mmu> mem, std::shared_ptr<calling_conv> conv);

#if defined(KERNEMUL_HAS_WHP)
	// hypermulator keeps its hook and step state per partition, so the whp backend has one cpu.
	inline constexpr std::size_t vcpu_count = 1;
#else
	inline constexpr std::size_t vcpu_count = 4;
#endif
