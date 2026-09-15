#pragma once
#include "../addr_space.hpp"
#include <unordered_map>

namespace arm64
{
	union virt_addr
	{
		std::uint64_t val;
		struct
		{
			std::uint64_t offset : 12;
			std::uint64_t l3     : 9;
			std::uint64_t l2     : 9;
			std::uint64_t l1     : 9;
			std::uint64_t l0     : 9;
			std::uint64_t sign   : 16;
		};
	};

	constexpr std::uint64_t desc_valid  = 1ull << 0;
	constexpr std::uint64_t desc_table  = 1ull << 1;  // table at L0-2, page at L3
	constexpr std::uint64_t desc_af     = 1ull << 10; // access flag
	constexpr std::uint64_t desc_sh_is  = 3ull << 8;  // inner shareable
	constexpr std::uint64_t desc_pxn    = 1ull << 53;
	constexpr std::uint64_t desc_uxn    = 1ull << 54;

	// AP[2:1] at bits 7:6 -- EL0 access is bit 6, read-only is bit 7.
	constexpr std::uint64_t desc_ap_el0 = 1ull << 6;
	constexpr std::uint64_t desc_ap_ro  = 1ull << 7;

	constexpr std::uint64_t desc_addr_mask = 0x0000'FFFF'FFFF'F000ull;

	struct addr_space : ::addr_space
	{
		addr_t alloc(std::size_t size, mem_prot prot) override;
		addr_t map_phys(addr_t pa, std::size_t size, mem_prot prot) override;

		// User and kernel level 0 indices are disjoint, so TTBR0_EL1 and TTBR1_EL1 share one table.
		addr_t ttbr_pa = 0;
		std::unordered_map<addr_t, addr_t> shadow;
		addr_t user_next_ = 0x10000;
		addr_t kernel_next_ = 0xFFFFF80000000000;
	};
}
