#include "registry.hpp"

#include "../util/util.hpp"
#include "../util/logs.hpp"

#include <algorithm>
#include <set>

// registry_key_t

void registry_key_t::set_value(const std::string_view name, const registry_type type,
	const void* data, const std::size_t size)
{
	auto& entry = values[std::string(name)];
	entry.type = type;
	entry.data.resize(size);

	if (data && size > 0)
	{
		std::memcpy(entry.data.data(), data, size);
	}
}

void registry_key_t::set_value(const std::string_view name, const registry_type type,
	const std::span<const std::uint8_t> data)
{
	set_value(name, type, data.data(), data.size());
}

const registry_value_t* registry_key_t::query_value(const std::string_view name) const
{
	const auto it = values.find(std::string(name));

	if (it == values.end())
	{
		return nullptr;
	}

	return &it->second;
}

bool registry_key_t::delete_value(const std::string_view name)
{
	return values.erase(std::string(name)) > 0;
}

void registry_key_t::set_dword(const std::string_view name, const std::uint32_t value)
{
	set_value(name, registry_type::dword, &value, sizeof(value));
}

void registry_key_t::set_qword(const std::string_view name, const std::uint64_t value)
{
	set_value(name, registry_type::qword, &value, sizeof(value));
}

void registry_key_t::set_string(const std::string_view name, const std::wstring_view value)
{
	const auto byte_length = (value.size() + 1) * sizeof(wchar_t);
	std::vector<std::uint8_t> buffer(byte_length, 0);
	std::memcpy(buffer.data(), value.data(), value.size() * sizeof(wchar_t));
	set_value(name, registry_type::sz, buffer.data(), buffer.size());
}

void registry_key_t::set_string(const std::string_view name, const std::string_view value)
{
	set_string(name, util::widen_string(value));
}

void registry_key_t::set_binary(const std::string_view name, const void* data, const std::size_t size)
{
	set_value(name, registry_type::binary, data, size);
}

void registry_key_t::set_binary(const std::string_view name, const std::span<const std::uint8_t> data)
{
	set_value(name, registry_type::binary, data.data(), data.size());
}

std::vector<std::string> registry_key_t::enumerate_values() const
{
	std::vector<std::string> result;
	result.reserve(values.size());

	for (const auto& [name, _] : values)
	{
		result.push_back(name);
	}

	std::sort(result.begin(), result.end());

	return result;
}

// registry_t

std::shared_ptr<registry_key_t> registry_t::open_key(const std::string_view path) const
{
	const auto it = keys_.find(std::string(path));

	if (it == keys_.end())
	{
		return {};
	}

	return it->second;
}

std::shared_ptr<registry_key_t> registry_t::create_key(const std::string_view path)
{
	const auto path_str = std::string(path);
	const auto it = keys_.find(path_str);

	if (it != keys_.end())
	{
		return it->second;
	}

	// create ancestor keys
	std::size_t pos = 0;

	while ((pos = path_str.find('/', pos)) != std::string::npos)
	{
		const auto ancestor = path_str.substr(0, pos);

		if (!keys_.contains(ancestor))
		{
			keys_[ancestor] = std::make_shared<registry_key_t>();
		}

		++pos;
	}

	auto key = std::make_shared<registry_key_t>();
	keys_[path_str] = key;

	GLOBAL_LOG("registry: created key '{}'", path_str);

	return key;
}

bool registry_t::delete_key(const std::string_view path)
{
	return keys_.erase(std::string(path)) > 0;
}

bool registry_t::key_exists(const std::string_view path) const
{
	return keys_.contains(std::string(path));
}

std::vector<std::string> registry_t::enumerate_subkeys(const std::string_view parent_path) const
{
	const auto prefix = std::string(parent_path) + "/";
	std::set<std::string> subkeys;

	for (const auto& [key_path, _] : keys_)
	{
		if (!key_path.starts_with(prefix))
		{
			continue;
		}

		const auto remainder = key_path.substr(prefix.size());
		const auto slash_pos = remainder.find('/');

		if (slash_pos == std::string::npos)
		{
			subkeys.insert(remainder);
		}
		else
		{
			subkeys.insert(remainder.substr(0, slash_pos));
		}
	}

	return { subkeys.begin(), subkeys.end() };
}

registry_t::path_type registry_t::normalize_path(const std::wstring_view guest_path)
{
	auto path = util::narrow_wstring(guest_path);

	for (auto& c : path)
	{
		if (c == '\\')
		{
			c = '/';
		}

		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}

	constexpr std::string_view registry_machine_prefix = "registry/machine/";

	if (path.starts_with(registry_machine_prefix))
	{
		path = path.substr(registry_machine_prefix.size());
	}

	// strip leading slash if present (e.g. from "\REGISTRY\MACHINE\...")
	if (!path.empty() && path.front() == '/')
	{
		path = path.substr(1);
	}

	// re-check after stripping leading slash
	if (path.starts_with(registry_machine_prefix))
	{
		path = path.substr(registry_machine_prefix.size());
	}

	// strip trailing slash
	while (!path.empty() && path.back() == '/')
	{
		path.pop_back();
	}

	return path;
}
