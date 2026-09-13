#pragma once
#include "../../emu/addr_space.hpp"
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>

// The executive pool. addr_space::alloc is page-granular and never frees, so
// this reserves from it in large runs and does its own splitting, coalescing
// and reuse inside them. The bookkeeping is host side rather than in a header
// in front of each block, so a driver overrunning its allocation cannot rewrite
// the allocator's own state.
class win_pool
{
public:
	explicit win_pool(addr_space& space) : space_(&space) {}

	struct allocation
	{
		// As the caller asked for it, not the aligned block it landed in.
		std::size_t size = 0;
		std::uint32_t tag = 0;
	};

	[[nodiscard]] addr_t allocate(std::size_t size, std::uint32_t tag, bool zero);

	std::optional<allocation> free(addr_t addr);

private:
	struct block
	{
		// Including the alignment padding, so blocks tile their run.
		std::size_t size = 0;
		std::size_t requested = 0;
		std::uint32_t tag = 0;
		bool free = true;
	};

	using block_iter = std::map<addr_t, block>::iterator;

	block_iter reserve(std::size_t size);

	addr_space* space_;
	std::mutex mtx_;

	// Free and busy alike, ordered by address: neighbours here are neighbours
	// in memory exactly when one ends where the next starts.
	std::map<addr_t, block> blocks_;
};

[[nodiscard]] std::string pool_tag_name(std::uint32_t tag);
