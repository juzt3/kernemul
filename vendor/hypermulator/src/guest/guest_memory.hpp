#pragma once
#include <cstdint>

namespace hm
{
	using addr_t = std::uint64_t;

	enum class mem_copy_dir : std::uint8_t
	{
		read,
		write
	};

	enum mem_prot : std::uint8_t
	{
		prot_none = 0,
		prot_read = 1,
		prot_write = 2,
		prot_rw = prot_read | prot_write,
		prot_exec = 4,
		prot_rx = prot_read | prot_exec,
		prot_wx = prot_write | prot_exec,
		prot_rwx = prot_read | prot_write | prot_exec
	};

	constexpr mem_prot operator|(mem_prot a, mem_prot b) { return static_cast<mem_prot>(static_cast<std::uint8_t>(a) | static_cast<std::uint8_t>(b)); }
	constexpr mem_prot operator&(mem_prot a, mem_prot b) { return static_cast<mem_prot>(static_cast<std::uint8_t>(a) & static_cast<std::uint8_t>(b)); }
	constexpr mem_prot operator~(mem_prot a) { return static_cast<mem_prot>(~static_cast<std::uint8_t>(a) & prot_rwx); }
	constexpr mem_prot& operator|=(mem_prot& a, mem_prot b) { return a = a | b; }
	constexpr mem_prot& operator&=(mem_prot& a, mem_prot b) { return a = a & b; }

	struct mapped_mem
	{
		void* host_buf;
		mem_prot prot;

		// A range is mapped with one host allocation and one WHvMapGpaRange, then recorded a page
		// at a time so a hook can still re-protect a single page. Only the page the allocation
		// starts at owns it, so unmapping frees it once rather than once per page.
		bool owns_host_buf = false;
	};
}
