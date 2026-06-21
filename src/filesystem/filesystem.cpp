#include "filesystem.hpp"
#include "../util/file.hpp"
#include "../util/logs.hpp"

#include <filesystem>
#include <map>

std::span<const std::uint8_t> file_t::read() const
{
	return buffer();
}

void file_t::write(const std::span<const std::uint8_t> buffer)
{
	buffer_ = { buffer.begin(), buffer.end() };
}

std::size_t file_t::size() const noexcept
{
	return buffer_.size();
}

std::span<std::uint8_t> file_t::buffer()
{
	return buffer_;
}

std::span<const std::uint8_t> file_t::buffer() const
{
	return buffer_;
}

bool file_t::is_directory() const noexcept
{
	return is_directory_;
}

filesystem_t::path_type filesystem_t::normalize(path_type path)
{
	for (auto& c : path)
	{
		if (c == '\\')
		{
			c = '/';
		}

		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}

	while (!path.empty() && path.back() == '/')
	{
		path.pop_back();
	}

	return path;
}

std::shared_ptr<file_t> filesystem_t::open_at(const path_type& path)
{
	const auto normalized = normalize(path);
	const auto it = list_.find(normalized);

	if (it == std::end(list_))
	{
		return {};
	}

	return it->second;
}

std::shared_ptr<file_t> filesystem_t::open_directory_at(const path_type& path)
{
	const auto normalized = normalize(path);

	if (const auto it = list_.find(normalized); it != std::end(list_) && it->second && it->second->is_directory())
	{
		return it->second;
	}

	if (!directory_exists(normalized))
	{
		return {};
	}

	return std::make_shared<file_t>(file_t::directory_tag);
}

std::shared_ptr<file_t> filesystem_t::create_at(const path_type& path)
{
	const auto normalized = normalize(path);
	const auto file = std::make_shared<file_t>();

	list_[normalized] = file;

	return file;
}

std::shared_ptr<file_t> filesystem_t::create_directory_at(const path_type& path)
{
	const auto normalized = normalize(path);
	const auto file = std::make_shared<file_t>(file_t::directory_tag);

	list_[normalized] = file;

	return file;
}

bool filesystem_t::delete_at(const path_type& path)
{
	const auto normalized = normalize(path);
	const auto it = list_.find(normalized);

	if (it == std::end(list_))
	{
		return false;
	}

	if (1 < it->second.use_count())
	{
		return false;
	}

	list_.erase(it);

	return true;
}

bool filesystem_t::exists(const path_type& path) const
{
	return list_.contains(normalize(path));
}

bool filesystem_t::directory_exists(const path_type& path) const
{
	const auto normalized = normalize(path);

	if (normalized.empty())
	{
		return true;
	}

	if (const auto it = list_.find(normalized); it != std::end(list_) && it->second && it->second->is_directory())
	{
		return true;
	}

	std::string prefix = normalized;

	if (prefix.back() != '/')
	{
		prefix.push_back('/');
	}

	for (const auto& [key, value] : list_)
	{
		if (key.starts_with(prefix))
		{
			return true;
		}
	}

	return false;
}

std::vector<filesystem_t::directory_entry_t> filesystem_t::list_directory(const path_type& path) const
{
	std::string prefix = normalize(path);

	if (!prefix.empty() && prefix.back() != '/')
	{
		prefix.push_back('/');
	}

	std::map<std::string, directory_entry_t> entries;

	for (const auto& [key, value] : list_)
	{
		if (!key.starts_with(prefix))
		{
			continue;
		}

		const auto rest = key.substr(prefix.size());

		if (rest.empty())
		{
			continue;
		}

		const auto slash = rest.find('/');

		if (slash == std::string::npos)
		{
			const bool is_directory = value && value->is_directory();

			auto& entry = entries[rest];
			entry.name = rest;
			entry.is_directory = entry.is_directory || is_directory;
			entry.size = is_directory ? 0 : (value ? value->size() : 0);
		}
		else
		{
			const auto name = rest.substr(0, slash);

			auto& entry = entries[name];
			entry.name = name;
			entry.is_directory = true;
		}
	}

	std::vector<directory_entry_t> result;
	result.reserve(entries.size());

	for (auto& [name, entry] : entries)
	{
		result.push_back(std::move(entry));
	}

	return result;
}

bool filesystem_t::load_at(const std::string& host_path, const path_type& virtual_path)
{
	std::filesystem::path vfs_path = std::filesystem::path("vfs").append(host_path);

	if (host_path.starts_with("vfs"))
	{
		vfs_path = host_path;
	}

	auto buffer = util::read_file(vfs_path);

	if (!buffer)
	{
		GLOBAL_WARN_LOG("filesystem: failed to open host file '{}'", vfs_path.string());
		return false;
	}

	const auto file_size = buffer->size();
	list_[normalize(virtual_path)] = std::make_shared<file_t>(std::move(*buffer));

	GLOBAL_LOG("filesystem: loaded '{}' -> '{}' ({} bytes)", host_path, virtual_path, file_size);

	return true;
}

bool filesystem_t::load_directory_at(const std::string& host_path, const path_type& virtual_path)
{
	std::error_code ec;

	const std::filesystem::path vfs_path = std::filesystem::path("vfs").append(host_path);

	const std::filesystem::path host_root(vfs_path);

	if (!std::filesystem::is_directory(host_root, ec))
	{
		GLOBAL_WARN_LOG("filesystem: host directory '{}' not found", host_path);
		return false;
	}

	const auto base = normalize(virtual_path);

	list_[base] = std::make_shared<file_t>(file_t::directory_tag);

	std::size_t loaded_files = 0;
	std::size_t loaded_directories = 1;

	for (auto it = std::filesystem::recursive_directory_iterator(host_root, std::filesystem::directory_options::skip_permission_denied, ec);
		it != std::filesystem::recursive_directory_iterator(); it.increment(ec))
	{
		if (ec)
		{
			GLOBAL_WARN_LOG("filesystem: iteration error under '{}': {}", host_path, ec.message());
			ec.clear();
			continue;
		}

		const auto relative = std::filesystem::relative(it->path(), host_root, ec);

		if (ec)
		{
			GLOBAL_WARN_LOG("filesystem: relative path error for '{}': {}", it->path().string(), ec.message());
			ec.clear();
			continue;
		}

		auto child = base.empty() ? normalize(relative.string())
			: base + "/" + normalize(relative.string());

		if (it->is_directory(ec))
		{
			list_[child] = std::make_shared<file_t>(file_t::directory_tag);
			++loaded_directories;
			continue;
		}

		if (!it->is_regular_file(ec))
		{
			continue;
		}

		if (load_at(it->path().string(), child))
		{
			++loaded_files;
		}
	}

	GLOBAL_LOG("filesystem: loaded directory '{}' -> '{}' ({} files, {} directories)",
		host_path, base, loaded_files, loaded_directories);

	return true;
}