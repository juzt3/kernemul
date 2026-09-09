#pragma once
#include <cstdint>

using addr_t = std::uint64_t;

enum mem_prot : std::uint8_t
{
	prot_none = 0,
	prot_read = 1,
	prot_write = 2,
	prot_exec = 4,
	prot_supervisor = 8,
	prot_rw = prot_read | prot_write,
	prot_rx = prot_read | prot_exec,
	prot_wx = prot_write | prot_exec,
	prot_rwx = prot_read | prot_write | prot_exec
};

constexpr mem_prot operator|(mem_prot a, mem_prot b) { return static_cast<mem_prot>(static_cast<std::uint8_t>(a) | static_cast<std::uint8_t>(b)); }
constexpr mem_prot operator&(mem_prot a, mem_prot b) { return static_cast<mem_prot>(static_cast<std::uint8_t>(a) & static_cast<std::uint8_t>(b)); }
constexpr mem_prot operator~(mem_prot a) { return static_cast<mem_prot>(~static_cast<std::uint8_t>(a)); }
constexpr mem_prot& operator|=(mem_prot& a, mem_prot b) { return a = a | b; }
constexpr mem_prot& operator&=(mem_prot& a, mem_prot b) { return a = a & b; }
