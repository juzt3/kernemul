#include "user_memory.hpp"

#include "../util/logs.hpp"

#include <algorithm>

using status_type = user::memory_manager_t::status_type;

constexpr status_type status_success = 0x00000000;
constexpr status_type status_invalid_parameter = 0xC000000D;
constexpr status_type status_no_memory = 0xC0000017;
constexpr status_type status_conflicting_addresses = 0xC0000018;
constexpr status_type status_unable_to_free = 0xC000001C;
constexpr status_type status_memory_not_allocated = 0xC00000A0;

constexpr emulator_t::address_type user_address_limit = 0x00007FFFFFFEFFFF;
constexpr emulator_t::size_type allocation_granularity = 0x10000;

user::memory_manager_t::memory_manager_t(std::shared_ptr<emulator_t> emulator)
	: emulator_(std::move(emulator))
{
}

emulator_t::size_type user::memory_manager_t::align_to_page(const emulator_t::size_type size)
{
	return (size + emulator_t::page_size - 1) & ~(emulator_t::page_size - 1);
}

emulator_t::address_type user::memory_manager_t::align_to_allocation(const emulator_t::address_type address)
{
	return address & ~(allocation_granularity - 1);
}

protection_t user::memory_manager_t::to_emulator_protection(const std::uint32_t win_protection)
{
	const auto base = win_protection & 0xFF;

	switch (base)
	{
	case page_noaccess:
		return prot_read;
	case page_readonly:
		return prot_read;
	case page_readwrite:
	case page_writecopy:
		return prot_read_write;
	case page_execute:
		return prot_execute;
	case page_execute_read:
		return static_cast<protection_t>(prot_execute | prot_read);
	case page_execute_readwrite:
	case page_execute_writecopy:
		return prot_all;
	default:
		return prot_read_write;
	}
}

user::memory_manager_t::reservation_map::iterator
user::memory_manager_t::find_reservation(const emulator_t::address_type address)
{
	if (reservations_.empty())
	{
		return reservations_.end();
	}

	auto upper = reservations_.upper_bound(address);

	if (upper == reservations_.begin())
	{
		return reservations_.end();
	}

	auto entry = std::prev(upper);

	if (address >= entry->first + entry->second.size)
	{
		return reservations_.end();
	}

	return entry;
}

user::memory_manager_t::reservation_map::const_iterator
user::memory_manager_t::find_reservation(const emulator_t::address_type address) const
{
	return const_cast<memory_manager_t*>(this)->find_reservation(address);
}



user::memory_manager_t::status_type user::memory_manager_t::allocate(
	emulator_t::address_type& base_address,
	emulator_t::size_type& region_size,
	const std::uint32_t allocation_type,
	const std::uint32_t protection,
	const emulator_t::size_type alignment)
{
	const auto aligned_size = align_to_page(region_size);

	if (aligned_size == 0)
	{
		return status_invalid_parameter;
	}

	const bool do_reserve = (allocation_type & mem_reserve) != 0;
	const bool do_commit = (allocation_type & mem_commit) != 0;

	if (!do_reserve && !do_commit)
	{
		return status_invalid_parameter;
	}

	// commit within an existing reservation (no MEM_RESERVE flag)
	if (do_commit && !do_reserve && base_address != 0)
	{
		const auto page_aligned = base_address & ~(emulator_t::page_size - 1);
		auto it = find_reservation(page_aligned);

		if (it != reservations_.end())
		{
			const auto res_end = it->first + it->second.size;

			if (page_aligned + aligned_size > res_end)
			{
				GLOBAL_WARN_LOG("user_memory: commit 0x{:X}+0x{:X} exceeds reservation end 0x{:X}",
					page_aligned, aligned_size, res_end);
				return status_conflicting_addresses;
			}

			const auto emu_prot = to_emulator_protection(protection);
			const auto commit_end = page_aligned + aligned_size;
			auto& committed = it->second.committed;

			// split existing committed subregions at commit boundaries
			for (auto ci = committed.begin(); ci != committed.end(); ++ci)
			{
				for (const auto split_point : {page_aligned, commit_end})
				{
					const auto sub_base = ci->first;
					const auto sub_end = sub_base + ci->second.size;

					if (split_point > sub_base && split_point < sub_end)
					{
						const auto first_size = split_point - sub_base;
						const auto second_size = ci->second.size - first_size;
						ci->second.size = first_size;

						committed[split_point] = committed_subregion_t
						{
							.size = second_size,
							.protection = ci->second.protection,
						};
					}
				}
			}

			// only map gaps between existing committed subregions
			emulator_t::address_type last_end = page_aligned;

			for (auto ci = committed.lower_bound(page_aligned); ci != committed.end(); ++ci)
			{
				if (ci->first >= commit_end)
				{
					break;
				}

				if (ci->first > last_end)
				{
					const auto gap_size = ci->first - last_end;

					if (!(protection & page_guard))
					{
						const auto error = emulator_->map_virtual_memory(last_end, gap_size, emu_prot, true);

						if (error)
						{
							GLOBAL_WARN_LOG("user_memory: failed to commit gap 0x{:X}+0x{:X}", last_end, gap_size);
							return status_conflicting_addresses;
						}
					}

					committed[last_end] = committed_subregion_t
					{
						.size = gap_size,
						.protection = protection,
					};
				}

				if (!(protection & page_guard))
				{
					static_cast<void>(emulator_->protect_virtual_memory(ci->first, ci->second.size, emu_prot));
				}
				ci->second.protection = protection;
				last_end = ci->first + ci->second.size;
			}

			// map the trailing gap after the last committed subregion
			if (last_end < commit_end)
			{
				const auto gap_size = commit_end - last_end;

				if (!(protection & page_guard))
				{
					const auto error = emulator_->map_virtual_memory(last_end, gap_size, emu_prot, true);

					if (error)
					{
						GLOBAL_WARN_LOG("user_memory: failed to commit trailing 0x{:X}+0x{:X}", last_end, gap_size);
						return status_conflicting_addresses;
					}
				}

				committed[last_end] = committed_subregion_t
				{
					.size = gap_size,
					.protection = protection,
				};
			}

			// merge adjacent committed subregions with same protection
			for (auto ci = committed.begin(); ci != committed.end();)
			{
				auto next = std::next(ci);

				if (next == committed.end())
				{
					break;
				}

				if (ci->first + ci->second.size == next->first
					&& ci->second.protection == next->second.protection)
				{
					ci->second.size += next->second.size;
					committed.erase(next);
				}
				else
				{
					++ci;
				}
			}

			base_address = page_aligned;
			region_size = aligned_size;

			GLOBAL_LOG("user_memory: committed 0x{:X} bytes at 0x{:X} (prot=0x{:X})",
				aligned_size, page_aligned, protection);

			return status_success;
		}

		// no reservation found - create a standalone commit+reserve for compatibility
		GLOBAL_LOG("user_memory: commit at 0x{:X} has no reservation, creating standalone", page_aligned);
	}

	// new reservation (with optional immediate commit)
	emulator_t::address_type target = base_address;

	if (target == 0)
	{
		const auto effective_alignment = alignment > allocation_granularity ? alignment : allocation_granularity;
		const auto align_mask = effective_alignment - 1;

		target = (next_free_address_ + align_mask) & ~align_mask;
		next_free_address_ = target + aligned_size;
	}
	else
	{
		if (do_reserve)
		{
			target = align_to_allocation(target);
		}
		else
		{
			target = target & ~(emulator_t::page_size - 1);
		}
	}

	// check for overlapping reservations
	const auto overlap = find_reservation(target);
	if (overlap != reservations_.end() && overlap->first != target)
	{
		// target falls inside an existing reservation but isn't at its base
		if (do_reserve)
		{
			return status_conflicting_addresses;
		}
	}

	if (do_commit)
	{
		if (!(protection & page_guard))
		{
			const auto emu_prot = to_emulator_protection(protection);
			const auto error = emulator_->map_virtual_memory(target, aligned_size, emu_prot, true);

			if (error)
			{
				GLOBAL_WARN_LOG("user_memory: failed to map 0x{:X} bytes at 0x{:X}", aligned_size, target);
				return status_conflicting_addresses;
			}
		}
	}

	reservation_t reservation
	{
		.size = aligned_size,
		.initial_protection = protection,
		.type = mem_private,
		.committed = {},
	};

	if (do_commit)
	{
		reservation.committed[target] = committed_subregion_t
		{
			.size = aligned_size,
			.protection = protection,
		};
	}

	reservations_[target] = std::move(reservation);

	base_address = target;
	region_size = aligned_size;

	if (target + aligned_size > next_free_address_ && target <= next_free_address_)
	{
		next_free_address_ = align_to_allocation(target + aligned_size);
	}

	GLOBAL_LOG("user_memory: {} 0x{:X} bytes at 0x{:X} (prot=0x{:X})",
		do_commit ? "allocated" : "reserved", aligned_size, target, protection);

	return status_success;
}

user::memory_manager_t::status_type user::memory_manager_t::free(
	emulator_t::address_type& base_address,
	emulator_t::size_type& region_size,
	const std::uint32_t free_type)
{
	if (free_type & mem_release)
	{
		if (region_size != 0)
		{
			return status_invalid_parameter;
		}

		const auto page_aligned = base_address & ~(emulator_t::page_size - 1);

		auto it = find_reservation(page_aligned);

		if (it == reservations_.end())
		{
			return status_unable_to_free;
		}

		if (it->second.type == mem_image || it->second.type == mem_mapped)
		{
			return status_unable_to_free;
		}

		if (page_aligned != it->first)
		{
			return status_unable_to_free;
		}

		for (const auto& [sub_base, sub_region] : it->second.committed)
		{
			static_cast<void>(emulator_->unmap_virtual_memory(sub_base, sub_region.size));
		}

		GLOBAL_LOG("user_memory: released 0x{:X} bytes at 0x{:X}", it->second.size, it->first);
		region_size = it->second.size;
		base_address = it->first;
		reservations_.erase(it);

		return status_success;
	}

	if (free_type & mem_decommit)
	{
		const auto page_aligned = base_address & ~(emulator_t::page_size - 1);
		auto decommit_size = align_to_page(region_size + (base_address - page_aligned));

		auto it = find_reservation(page_aligned);

		if (it == reservations_.end())
		{
			return status_memory_not_allocated;
		}

		if (decommit_size == 0)
		{
			if (it->first != page_aligned)
			{
				return status_unable_to_free;
			}

			decommit_size = it->second.size;
		}

		const auto decommit_end = page_aligned + decommit_size;
		auto& committed = it->second.committed;

		auto sub_it = committed.begin();
		while (sub_it != committed.end())
		{
			const auto sub_base = sub_it->first;
			const auto sub_end = sub_base + sub_it->second.size;
			const auto sub_prot = sub_it->second.protection;

			if (sub_base >= decommit_end)
			{
				break;
			}

			if (sub_end <= page_aligned)
			{
				++sub_it;
				continue;
			}

			const auto unmap_start = std::max(sub_base, page_aligned);
			const auto unmap_end = std::min(sub_end, decommit_end);
			static_cast<void>(emulator_->unmap_virtual_memory(unmap_start, unmap_end - unmap_start));

			if (sub_base < page_aligned && sub_end > decommit_end)
			{
				sub_it->second.size = page_aligned - sub_base;
				committed[decommit_end] = committed_subregion_t
				{
					.size = sub_end - decommit_end,
					.protection = sub_prot,
				};
				break;
			}
			else if (sub_base < page_aligned)
			{
				sub_it->second.size = page_aligned - sub_base;
				++sub_it;
			}
			else if (sub_end > decommit_end)
			{
				committed[decommit_end] = committed_subregion_t
				{
					.size = sub_end - decommit_end,
					.protection = sub_prot,
				};
				sub_it = committed.erase(sub_it);
				break;
			}
			else
			{
				sub_it = committed.erase(sub_it);
			}
		}

		base_address = page_aligned;
		region_size = decommit_size;

		GLOBAL_LOG("user_memory: decommitted 0x{:X} bytes at 0x{:X}", decommit_size, page_aligned);

		return status_success;
	}

	return status_invalid_parameter;
}

user::memory_manager_t::status_type user::memory_manager_t::protect(
	emulator_t::address_type& base_address,
	emulator_t::size_type& region_size,
	const std::uint32_t new_protection,
	std::uint32_t& old_protection)
{
	const auto aligned_address = base_address & ~(emulator_t::page_size - 1);
	const auto aligned_size = align_to_page(region_size + (base_address - aligned_address));

	old_protection = page_readwrite;

	const auto emu_prot = to_emulator_protection(new_protection);

	auto res_it = find_reservation(aligned_address);

	if (res_it != reservations_.end())
	{
		auto& committed = res_it->second.committed;
		const auto protect_end = aligned_address + aligned_size;

		// find committed sub-region containing this address
		for (auto it = committed.begin(); it != committed.end(); ++it)
		{
			const auto sub_base = it->first;
			const auto sub_end = sub_base + it->second.size;

			if (aligned_address >= sub_base && aligned_address < sub_end)
			{
				old_protection = it->second.protection;

				// split the subregion if the protect range doesn't cover the whole thing
				if (aligned_address == sub_base && protect_end >= sub_end)
				{
					// exact match or covers entire subregion
					it->second.protection = new_protection;
				}
				else
				{
					const auto orig_protection = it->second.protection;

					if (aligned_address > sub_base)
					{
						// left portion keeps original protection
						it->second.size = aligned_address - sub_base;

						// middle portion gets new protection
						committed[aligned_address] = committed_subregion_t
						{
							.size = std::min(protect_end, sub_end) - aligned_address,
							.protection = new_protection,
						};

						if (protect_end < sub_end)
						{
							// right portion keeps original protection
							committed[protect_end] = committed_subregion_t
							{
								.size = sub_end - protect_end,
								.protection = orig_protection,
							};
						}
					}
					else
					{
						// aligned_address == sub_base but protect_end < sub_end
						it->second.size = protect_end - sub_base;
						it->second.protection = new_protection;

						// remainder keeps original protection
						committed[protect_end] = committed_subregion_t
						{
							.size = sub_end - protect_end,
							.protection = orig_protection,
						};
					}
				}

				if (new_protection & page_guard)
				{
					static_cast<void>(emulator_->unmap_virtual_memory(aligned_address, aligned_size));
				}
				else if (old_protection & page_guard)
				{
					static_cast<void>(emulator_->map_virtual_memory(aligned_address, aligned_size, emu_prot, true));
				}
				else
				{
					static_cast<void>(emulator_->protect_virtual_memory(aligned_address, aligned_size, emu_prot));
				}

				base_address = aligned_address;
				region_size = aligned_size;

				GLOBAL_LOG("user_memory: protect 0x{:X}+0x{:X}: 0x{:X} -> 0x{:X}",
					aligned_address, aligned_size, old_protection, new_protection);

				return status_success;
			}
		}

		// address is reserved but not committed - update reservation protection
		old_protection = res_it->second.initial_protection;
		base_address = aligned_address;
		region_size = aligned_size;

		GLOBAL_LOG("user_memory: protect 0x{:X}+0x{:X}: 0x{:X} -> 0x{:X} (reserved)",
			aligned_address, aligned_size, old_protection, new_protection);

		return status_success;
	}

	// untracked region - update page table protection bits for compatibility
	static_cast<void>(emulator_->protect_virtual_memory(aligned_address, aligned_size, emu_prot));

	base_address = aligned_address;
	region_size = aligned_size;

	GLOBAL_LOG("user_memory: protect 0x{:X}+0x{:X}: (untracked) -> 0x{:X}",
		aligned_address, aligned_size, new_protection);

	return status_success;
}

user::memory_manager_t::status_type user::memory_manager_t::query_basic(
	const emulator_t::address_type address,
	memory_basic_information_t& info)
{
	info = {};
	info.base_address = address & ~(emulator_t::page_size - 1);

	auto res_it = find_reservation(address);

	if (res_it == reservations_.end())
	{
		info.state = mem_free;
		info.protect = page_noaccess;
		info.type = 0;

		const auto page_aligned = info.base_address;
		auto next = reservations_.upper_bound(address);

		if (next != reservations_.end())
		{
			info.region_size = next->first - page_aligned;
		}
		else
		{
			constexpr emulator_t::address_type user_address_limit = 0x7FFFFFFEFFFF;
			info.region_size = (user_address_limit + 1) - page_aligned;
		}

		return status_success;
	}

	const auto res_base = res_it->first;
	const auto& reservation = res_it->second;

	// check if the address falls within a committed sub-region
	const auto page_aligned_addr = address & ~(emulator_t::page_size - 1);

	for (const auto& [sub_base, sub_region] : reservation.committed)
	{
		if (address >= sub_base && address < sub_base + sub_region.size)
		{
			info.base_address = page_aligned_addr;
			info.allocation_base = res_base;
			info.allocation_protect = reservation.initial_protection;
			info.region_size = (sub_base + sub_region.size) - page_aligned_addr;
			info.state = mem_commit;
			info.protect = sub_region.protection;
			info.type = reservation.type;
			return status_success;
		}
	}

	// address is within reservation but not committed
	info.base_address = address & ~(emulator_t::page_size - 1);
	info.allocation_base = res_base;
	info.allocation_protect = reservation.initial_protection;
	info.state = mem_reserve;
	info.protect = page_noaccess;
	info.type = reservation.type;

	// calculate reserved region size (gap between committed sub-regions)
	auto gap_end = res_base + reservation.size;

	for (const auto& [sub_base, sub_region] : reservation.committed)
	{
		if (sub_base > info.base_address)
		{
			gap_end = sub_base;
			break;
		}
	}

	info.region_size = gap_end - info.base_address;

	return status_success;
}

void user::memory_manager_t::register_image(
	const emulator_t::address_type base_address,
	const emulator_t::size_type size)
{
	const auto aligned_size = align_to_page(size);

	reservation_t reservation
	{
		.size = aligned_size,
		.initial_protection = page_execute_readwrite,
		.type = mem_image,
		.committed = {},
	};

	reservation.committed[base_address] = committed_subregion_t
	{
		.size = aligned_size,
		.protection = page_execute_readwrite,
	};

	reservations_[base_address] = std::move(reservation);

	GLOBAL_LOG("user_memory: registered image 0x{:X}+0x{:X}", base_address, aligned_size);
}

void user::memory_manager_t::register_mapped(
	const emulator_t::address_type base_address,
	const emulator_t::size_type size,
	const std::uint32_t protection)
{
	const auto aligned_size = align_to_page(size);

	reservation_t reservation
	{
		.size = aligned_size,
		.initial_protection = protection,
		.type = mem_mapped,
		.committed = {},
	};

	reservation.committed[base_address] = committed_subregion_t
	{
		.size = aligned_size,
		.protection = protection,
	};

	reservations_[base_address] = std::move(reservation);
}

emulator_t::address_type user::memory_manager_t::allocate_pages(
	const emulator_t::size_type size,
	const std::uint32_t protection)
{
	emulator_t::address_type base = 0;
	auto region_size = size;

	const auto status = allocate(base, region_size, mem_commit | mem_reserve, protection);

	if (status != status_success)
	{
		return 0;
	}

	return base;
}

bool user::memory_manager_t::try_demand_commit(const emulator_t::address_type faulting_address)
{
	const auto page_base = faulting_address & ~(emulator_t::page_size - 1);

	auto res_it = find_reservation(faulting_address);

	if (res_it == reservations_.end())
	{
		return false;
	}

	const auto res_end = res_it->first + res_it->second.size;

	if (page_base < res_it->first || page_base >= res_end)
	{
		return false;
	}

	for (const auto& [sub_base, sub_region] : res_it->second.committed)
	{
		if (page_base >= sub_base && page_base < sub_base + sub_region.size)
		{
			return false;
		}
	}

	const auto emu_prot = to_emulator_protection(res_it->second.initial_protection);
	const auto error = emulator_->map_virtual_memory(page_base, emulator_t::page_size, emu_prot, true);

	if (error)
	{
		return false;
	}

	res_it->second.committed[page_base] = committed_subregion_t
	{
		.size = emulator_t::page_size,
		.protection = res_it->second.initial_protection,
	};

	GLOBAL_LOG("user_memory: demand-committed page at 0x{:X} (reservation 0x{:X}+0x{:X})",
		page_base, res_it->first, res_it->second.size);

	return true;
}

bool user::memory_manager_t::try_handle_guard_page(const emulator_t::address_type faulting_address)
{
	const auto page_base = faulting_address & ~(emulator_t::page_size - 1);

	auto res_it = find_reservation(faulting_address);

	if (res_it == reservations_.end())
	{
		return false;
	}

	for (auto& [sub_base, sub_region] : res_it->second.committed)
	{
		if (page_base >= sub_base && page_base < sub_base + sub_region.size)
		{
			if (!(sub_region.protection & page_guard))
			{
				return false;
			}

			sub_region.protection &= ~page_guard;
			const auto emu_prot = to_emulator_protection(sub_region.protection);
			const auto error = emulator_->map_virtual_memory(page_base, emulator_t::page_size, emu_prot, true);

			if (error)
			{
				return false;
			}

			GLOBAL_LOG("user_memory: guard page hit at 0x{:X}, stripped guard (prot=0x{:X})",
				page_base, sub_region.protection);

			return true;
		}
	}

	return false;
}

