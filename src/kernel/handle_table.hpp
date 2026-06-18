#pragma once
#include "../emulator/emulator.hpp"
#include "object_manager.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <unordered_map>

class handle_table_t
{
public:
	using handle_type = std::uint64_t;
	using access_type = std::uint32_t;

	struct handle_entry_t
	{
		emulator_t::address_type body_address;
		access_type access;
	};

	explicit handle_table_t(std::shared_ptr<emulator_t> emulator,
		std::shared_ptr<object_manager_t> object_manager);

	[[nodiscard]] handle_type create_handle(emulator_t::address_type body_address, access_type access);
	bool close_handle(handle_type handle);
	[[nodiscard]] std::optional<handle_entry_t> lookup_handle(handle_type handle) const;

	template <typename T>
	[[nodiscard]] std::shared_ptr<T> get_object_from_handle(handle_type handle) const
	{
		const auto entry = lookup_handle(handle);

		if (!entry)
		{
			return {};
		}

		return object_manager_->get_object<T>(entry->body_address);
	}

private:
	[[nodiscard]] handle_type allocate_handle();

	std::shared_ptr<emulator_t> emulator_;
	std::shared_ptr<object_manager_t> object_manager_;
	std::unordered_map<handle_type, handle_entry_t> handles_;
	handle_type next_handle_ = 4;
};
