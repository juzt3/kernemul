#include "pool.hpp"
#include <algorithm>
#include <vector>

namespace
{

// MEMORY_ALLOCATION_ALIGNMENT, which a driver putting an slist entry in a block depends on.
constexpr std::size_t pool_alignment = 16;

// Windows hands back a page aligned block for any request of a page or more, and drivers rely
// on it: they mask a pointer down to find the block it came from, or hand it to something that
// wants whole pages. Splitting a run at 16 bytes gives out addresses that break both.
constexpr std::size_t page_size = 0x1000;

constexpr std::size_t run_size = 0x100000;

constexpr std::size_t align_up(const std::size_t size, const std::size_t to)
{
	return (size + to - 1) & ~(to - 1);
}

}

std::string pool_tag_name(const std::uint32_t tag)
{
	std::string name;

	for (int i = 0; i < 4; ++i)
	{
		const auto c = static_cast<char>((tag >> (i * 8)) & 0xFF);
		name.push_back(c >= 0x20 && c < 0x7F ? c : '.');
	}

	return name;
}

win_pool::block_iter win_pool::reserve(const std::size_t size)
{
	const auto reserved = align_up(std::max(size, run_size), page_size);
	const auto base = space_->alloc(reserved, prot_rw | prot_supervisor);

	return blocks_.emplace(base, block{ .size = reserved }).first;
}

addr_t win_pool::allocate(const std::size_t size, const std::uint32_t tag, const bool zero)
{
	if (size == 0)
		return 0;

	const auto alignment = size >= page_size ? page_size : pool_alignment;
	const auto needed = align_up(size, pool_alignment);

	std::scoped_lock lock(mtx_);

	// First fit, but on the aligned address inside the block rather than the block's own start,
	// so a run that has been split at 16 bytes can still satisfy a page aligned request.
	auto it = blocks_.end();
	addr_t addr = 0;

	for (auto cur = blocks_.begin(); cur != blocks_.end(); ++cur)
	{
		if (!cur->second.free)
			continue;

		const auto aligned = align_up(cur->first, alignment);

		if (cur->second.size >= (aligned - cur->first) + needed)
		{
			it = cur;
			addr = aligned;
			break;
		}
	}

	if (it == blocks_.end())
	{
		// Room for the alignment padding as well, in case the run does not start aligned.
		it = reserve(needed + alignment);
		addr = align_up(it->first, alignment);
	}

	// Anything skipped to reach the aligned address stays free and usable by smaller requests.
	if (const auto lead = addr - it->first; lead > 0)
	{
		const auto rest = it->second.size - lead;

		it->second.size = lead;
		it = blocks_.emplace(addr, block{ .size = rest }).first;
	}

	auto& chosen = it->second;

	if (chosen.size > needed)
	{
		blocks_.emplace(addr + needed, block{ .size = chosen.size - needed });
		chosen.size = needed;
	}

	chosen.free = false;
	chosen.requested = size;
	chosen.tag = tag;

	if (zero)
	{
		const std::vector<std::uint8_t> zeros(size, 0);
		space_->write_mem(addr, zeros.data(), size);
	}

	return addr;
}

std::optional<win_pool::allocation> win_pool::free(const addr_t addr)
{
	std::scoped_lock lock(mtx_);

	const auto it = blocks_.find(addr);

	if (it == blocks_.end() || it->second.free)
		return std::nullopt;

	auto& freed = it->second;
	const allocation result{ freed.requested, freed.tag };

	freed.free = true;

	const auto next = std::next(it);

	if (next != blocks_.end() && next->second.free && addr + freed.size == next->first)
	{
		freed.size += next->second.size;
		blocks_.erase(next);
	}

	if (it != blocks_.begin())
	{
		const auto prev = std::prev(it);

		if (prev->second.free && prev->first + prev->second.size == addr)
		{
			prev->second.size += freed.size;
			blocks_.erase(it);
		}
	}

	return result;
}
