#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

enum class registry_type : std::uint32_t
{
	none      = 0,
	sz        = 1,
	expand_sz = 2,
	binary    = 3,
	dword     = 4,
	dword_be  = 5,
	link      = 6,
	multi_sz  = 7,
	qword     = 11,
};

struct registry_value_t
{
	registry_type type = registry_type::none;
	std::vector<std::uint8_t> data;
};

class registry_key_t
{
public:
	registry_key_t() = default;

	void set_value(std::string_view name, registry_type type, const void* data, std::size_t size);
	void set_value(std::string_view name, registry_type type, std::span<const std::uint8_t> data);
	[[nodiscard]] const registry_value_t* query_value(std::string_view name) const;
	bool delete_value(std::string_view name);

	void set_dword(std::string_view name, std::uint32_t value);
	void set_qword(std::string_view name, std::uint64_t value);
	void set_string(std::string_view name, std::wstring_view value);
	void set_string(std::string_view name, std::string_view value);
	void set_binary(std::string_view name, const void* data, std::size_t size);
	void set_binary(std::string_view name, std::span<const std::uint8_t> data);

	[[nodiscard]] std::vector<std::string> enumerate_values() const;

	std::unordered_map<std::string, registry_value_t> values;
};

class registry_t
{
public:
	using path_type = std::string;

	registry_t() = default;

	[[nodiscard]] std::shared_ptr<registry_key_t> open_key(std::string_view path) const;
	[[nodiscard]] std::shared_ptr<registry_key_t> create_key(std::string_view path);
	[[nodiscard]] bool delete_key(std::string_view path);
	[[nodiscard]] bool key_exists(std::string_view path) const;

	[[nodiscard]] std::vector<std::string> enumerate_subkeys(std::string_view parent_path) const;

	[[nodiscard]] static path_type normalize_path(std::wstring_view guest_path);

protected:
	std::unordered_map<path_type, std::shared_ptr<registry_key_t>> keys_;
};
