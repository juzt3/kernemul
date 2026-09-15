#pragma once
#include "../../emu/addr_space.hpp"
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>

// Bookkeeping is host side, so a driver overrunning its allocation cannot rewrite the allocator.
class win_pool
{
public:
	explicit win_pool(addr_space& space) : space_(&space) {}

	struct allocation
	{
		std::size_t size = 0;
		std::uint32_t tag = 0;
	};

	[[nodiscard]] addr_t allocate(std::size_t size, std::uint32_t tag, bool zero);

	std::optional<allocation> free(addr_t addr);

private:
	struct block
	{
		std::size_t size = 0;
		std::size_t requested = 0;
		std::uint32_t tag = 0;
		bool free = true;
	};

	using block_iter = std::map<addr_t, block>::iterator;

	block_iter reserve(std::size_t size);

	addr_space* space_;
	std::mutex mtx_;

	std::map<addr_t, block> blocks_;
};

[[nodiscard]] std::string pool_tag_name(std::uint32_t tag);

// 'Abcd' packed low byte first, which is how a tag is stored.
constexpr std::uint32_t pool_tag(const char (&name)[5])
{
	return static_cast<std::uint32_t>(static_cast<unsigned char>(name[0]))
		| static_cast<std::uint32_t>(static_cast<unsigned char>(name[1])) << 8
		| static_cast<std::uint32_t>(static_cast<unsigned char>(name[2])) << 16
		| static_cast<std::uint32_t>(static_cast<unsigned char>(name[3])) << 24;
}
