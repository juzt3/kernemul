#pragma once
#include "../emulator/emulator.hpp"
#include "../emulator/object.hpp"
#include "../kernel_def.hpp"
#include <string>

class mapped_image_t
{
public:
	using string_type = std::string;
	using address_type = emulator_t::address_type;
	using size_type = emulator_t::size_type;
	using symbol_map_type = std::unordered_map<string_type, address_type>;

	mapped_image_t(string_type name, const address_type base_address, const address_type entry_point, std::vector<std::uint8_t> buffer)
			:	name_(std::move(name)),
				base_address_(base_address),
				entry_point_(entry_point),
				buffer_(std::move(buffer)) { }

	[[nodiscard]] std::optional<address_type> find_symbol(const string_type& symbol_name) const
	{
		const auto it = symbols_.find(symbol_name);

		if (it != std::ranges::end(symbols_))
		{
			return it->second;
		}

		return std::nullopt;
	}

	void register_symbol(const string_type& symbol_name, const address_type address)
	{
		symbols_.try_emplace(symbol_name, address);
	}

	[[nodiscard]] const symbol_map_type& symbols() const
	{
		return symbols_;
	}

	[[nodiscard]] const string_type& name() const
	{
		return name_;
	}

	[[nodiscard]] address_type base_address() const
	{
		return base_address_;
	}

	[[nodiscard]] address_type entry_point() const
	{
		return entry_point_;
	}

	[[nodiscard]] size_type size() const
	{
		return buffer_.size();
	}

	[[nodiscard]] std::span<std::uint8_t> buffer()
	{
		return buffer_;
	}

	[[nodiscard]] std::span<const std::uint8_t> buffer() const
	{
		return buffer_;
	}

	[[nodiscard]] emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& table_entry()
	{
		return table_entry_;
	}

	[[nodiscard]] const emulator_object_t<_KLDR_DATA_TABLE_ENTRY>& table_entry() const
	{
		return table_entry_;
	}

	void set_table_entry(emulator_object_t<_KLDR_DATA_TABLE_ENTRY> object)
	{
		table_entry_ = std::move(object);
	}

protected:
	string_type name_;

	address_type base_address_;
	address_type entry_point_;

	std::vector<std::uint8_t> buffer_;
	symbol_map_type symbols_;

	emulator_object_t<_KLDR_DATA_TABLE_ENTRY> table_entry_;
};
