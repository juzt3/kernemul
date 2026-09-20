#pragma once
#include "types.hpp"
#include "../../util/string.hpp"
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>

namespace win {

struct api_set_namespace_entry
{
	std::uint32_t flags;
	std::uint32_t name_offset;
	std::uint32_t name_length;
	std::uint32_t hashed_length;
	std::uint32_t value_offset;
	std::uint32_t value_count;
};

struct api_set_value_entry
{
	std::uint32_t flags;
	std::uint32_t name_offset;
	std::uint32_t name_length;
	std::uint32_t value_offset;
	std::uint32_t value_length;
};

struct api_set_entry
{
	std::string host;

	// Six of the schema's names carry any of these, and they keep resolution from going in circles.
	std::vector<std::pair<std::string, std::string>> overrides;
};

struct api_set_map
{
	// Keyed by what the schema hashes: the name with its last dash-separated piece removed.
	std::unordered_map<std::string, api_set_entry, string_view_hash, std::equal_to<>> hosts;

	[[nodiscard]] bool empty() const noexcept { return hosts.empty(); }

	[[nodiscard]] static std::string hash_key(std::string_view name)
	{
		auto key = ascii_lower(name);

		if (key.ends_with(".dll"))
			key.resize(key.size() - 4);

		if (const auto dash = key.find_last_of('-'); dash != std::string::npos)
			key.resize(dash);

		return key;
	}

	[[nodiscard]] std::optional<std::string> resolve(const std::string_view name,
		const std::string_view importer = {}) const
	{
		const auto lower = ascii_lower(name);

		if (!lower.starts_with("api-ms-") && !lower.starts_with("ext-ms-"))
			return std::nullopt;

		const auto it = hosts.find(hash_key(lower));

		if (it == hosts.end())
			return std::nullopt;

		const auto from = ascii_lower(importer);

		for (const auto& [who, host] : it->second.overrides)
		{
			if (who == from)
				return host;
		}

		return it->second.host;
	}
};

// Every offset counts from the .apiset section; names are utf-16 and carry their own length.
inline api_set_map parse_api_set_map(const std::span<const std::uint8_t> section)
{
	api_set_map map;

	if (section.size() < sizeof(_API_SET_NAMESPACE))
		return map;

	const auto& ns = *reinterpret_cast<const _API_SET_NAMESPACE*>(section.data());

	if (ns.Version != 6)
	{
		LOG_WARN("api set schema version {} is not supported, so no import resolves through it",
			ns.Version);
		return map;
	}

	const auto str = [section](const std::uint32_t offset, const std::uint32_t bytes)
	{
		if (offset + bytes > section.size())
			return std::string{};

		return narrow_wstring(std::u16string_view(
			reinterpret_cast<const char16_t*>(section.data() + offset), bytes / sizeof(char16_t)));
	};

	for (std::uint32_t i = 0; i < ns.Count; ++i)
	{
		const auto entry_off = ns.EntryOffset + i * sizeof(api_set_namespace_entry);

		if (entry_off + sizeof(api_set_namespace_entry) > section.size())
			break;

		const auto& entry = *reinterpret_cast<const api_set_namespace_entry*>(
			section.data() + entry_off);

		if (!entry.value_count)
			continue;

		const auto name = str(entry.name_offset, entry.hashed_length);

		if (name.empty())
			continue;

		api_set_entry parsed;

		for (std::uint32_t v = 0; v < entry.value_count; ++v)
		{
			const auto value_off = entry.value_offset + v * sizeof(api_set_value_entry);

			if (value_off + sizeof(api_set_value_entry) > section.size())
				break;

			const auto& value = *reinterpret_cast<const api_set_value_entry*>(
				section.data() + value_off);

			auto host = str(value.value_offset, value.value_length);

			if (host.empty())
				continue;

			// The one naming no importer is what everyone else gets.
			if (auto who = str(value.name_offset, value.name_length); who.empty())
				parsed.host = std::move(host);
			else
				parsed.overrides.emplace_back(ascii_lower(who), std::move(host));
		}

		if (!parsed.host.empty() || !parsed.overrides.empty())
			map.hosts[ascii_lower(name)] = std::move(parsed);
	}

	return map;
}

} // namespace win
