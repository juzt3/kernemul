#pragma once
#include "../../emu/defs.hpp"
#include <cstdint>

// Not in the generated types: a WDK header the kernel never stores, same layout on both arches.
#pragma pack(push, 8)
struct mdl_t
{
	addr_t        next;
	std::int16_t  size;
	std::int16_t  mdl_flags;
	std::uint32_t alloc_processor;
	addr_t        process;
	addr_t        mapped_system_va;
	addr_t        start_va;
	std::uint32_t byte_count;
	std::uint32_t byte_offset;
};
#pragma pack(pop)

static_assert(sizeof(mdl_t) == 0x30);

enum mdl_flags : std::int16_t
{
	mdl_mapped_to_system_va     = 0x0001,
	mdl_pages_locked            = 0x0002,
	mdl_source_is_nonpaged_pool = 0x0004,
};

inline constexpr std::size_t mdl_page_size = 0x1000;

inline constexpr addr_t mdl_page_base(const addr_t addr)
{
	return addr & ~static_cast<addr_t>(mdl_page_size - 1);
}

inline constexpr std::size_t mdl_page_offset(const addr_t addr)
{
	return addr & (mdl_page_size - 1);
}

inline constexpr std::size_t mdl_page_count(const addr_t va, const std::size_t bytes)
{
	return (mdl_page_offset(va) + bytes + mdl_page_size - 1) / mdl_page_size;
}

inline constexpr std::size_t mdl_size(const addr_t va, const std::size_t bytes)
{
	return sizeof(mdl_t) + mdl_page_count(va, bytes) * sizeof(addr_t);
}
