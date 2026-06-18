#pragma once

#include "../emulator/emulator.hpp"

#include <cstdint>
#include <map>
#include <memory>

namespace user
{
	constexpr std::uint32_t mem_commit = 0x1000;
	constexpr std::uint32_t mem_reserve = 0x2000;
	constexpr std::uint32_t mem_decommit = 0x4000;
	constexpr std::uint32_t mem_release = 0x8000;
	constexpr std::uint32_t mem_free = 0x10000;
	constexpr std::uint32_t mem_top_down = 0x100000;

	constexpr std::uint32_t page_noaccess = 0x01;
	constexpr std::uint32_t page_readonly = 0x02;
	constexpr std::uint32_t page_readwrite = 0x04;
	constexpr std::uint32_t page_writecopy = 0x08;
	constexpr std::uint32_t page_execute = 0x10;
	constexpr std::uint32_t page_execute_read = 0x20;
	constexpr std::uint32_t page_execute_readwrite = 0x40;
	constexpr std::uint32_t page_execute_writecopy = 0x80;
	constexpr std::uint32_t page_guard = 0x100;

	constexpr std::uint32_t mem_image = 0x1000000;
	constexpr std::uint32_t mem_mapped = 0x40000;
	constexpr std::uint32_t mem_private = 0x20000;

	struct committed_subregion_t
	{
		emulator_t::size_type size;
		std::uint32_t protection;
	};

	struct reservation_t
	{
		emulator_t::size_type size;
		std::uint32_t initial_protection;
		std::uint32_t type;
		std::map<emulator_t::address_type, committed_subregion_t> committed;
	};

	struct memory_basic_information_t
	{
		std::uint64_t base_address;
		std::uint64_t allocation_base;
		std::uint32_t allocation_protect;
		std::uint32_t partition_id;
		std::uint64_t region_size;
		std::uint32_t state;
		std::uint32_t protect;
		std::uint32_t type;
	};

	class memory_manager_t
	{
	public:
		using status_type = std::uint32_t;

		explicit memory_manager_t(std::shared_ptr<emulator_t> emulator);

		status_type allocate(emulator_t::address_type& base_address,
			emulator_t::size_type& region_size,
			std::uint32_t allocation_type,
			std::uint32_t protection,
			emulator_t::size_type alignment = 0);

		status_type free(emulator_t::address_type& base_address,
			emulator_t::size_type& region_size,
			std::uint32_t free_type);

		status_type protect(emulator_t::address_type& base_address,
			emulator_t::size_type& region_size,
			std::uint32_t new_protection,
			std::uint32_t& old_protection);

		status_type query_basic(emulator_t::address_type address,
			memory_basic_information_t& info);

		void register_image(emulator_t::address_type base_address,
			emulator_t::size_type size);

		void register_mapped(emulator_t::address_type base_address,
			emulator_t::size_type size,
			std::uint32_t protection);

		emulator_t::address_type allocate_pages(emulator_t::size_type size,
			std::uint32_t protection = page_readwrite);

		bool try_demand_commit(emulator_t::address_type faulting_address);
		bool try_handle_guard_page(emulator_t::address_type faulting_address);

	private:
		using reservation_map = std::map<emulator_t::address_type, reservation_t>;

		std::shared_ptr<emulator_t> emulator_;
		emulator_t::address_type next_free_address_ = 0x100000000;

		reservation_map reservations_;

		reservation_map::iterator find_reservation(emulator_t::address_type address);
		reservation_map::const_iterator find_reservation(emulator_t::address_type address) const;

		static emulator_t::size_type align_to_page(emulator_t::size_type size);
		static emulator_t::address_type align_to_allocation(emulator_t::address_type address);
		static protection_t to_emulator_protection(std::uint32_t win_protection);
	};

	inline std::unique_ptr<memory_manager_t> memory_manager;
}
