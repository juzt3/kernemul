#include "filesystem.hpp"

#include "../util/logs.hpp"

#include <filesystem>
#include <fstream>

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

std::shared_ptr<file_t> filesystem_t::open_at(const path_type& path)
{
	const auto it = list_.find(path);

	if (it == std::end(list_))
	{
		return {};
	}

	return it->second;
}

std::shared_ptr<file_t> filesystem_t::open_directory_at(const path_type& path)
{
	if (const auto it = list_.find(path); it != std::end(list_) && it->second && it->second->is_directory())
	{
		return it->second;
	}

	if (!directory_exists(path))
	{
		return {};
	}

	return std::make_shared<file_t>(file_t::directory_tag);
}

std::shared_ptr<file_t> filesystem_t::create_at(const path_type& path)
{
	const auto file = std::make_shared<file_t>();

	list_[path] = file;

	return file;
}

std::shared_ptr<file_t> filesystem_t::create_directory_at(const path_type& path)
{
	const auto file = std::make_shared<file_t>(file_t::directory_tag);

	list_[path] = file;

	return file;
}

bool filesystem_t::delete_at(const path_type& path)
{
	const auto it = list_.find(path);

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
	return list_.contains(path);
}

bool filesystem_t::directory_exists(const path_type& path) const
{
	if (path.empty())
	{
		return true;
	}

	if (const auto it = list_.find(path); it != std::end(list_) && it->second && it->second->is_directory())
	{
		return true;
	}

	std::string prefix = path;

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

bool filesystem_t::load_at(const std::string& host_path, const path_type& virtual_path)
{
	std::ifstream file(host_path, std::ios::binary | std::ios::ate);

	if (!file.is_open())
	{
		GLOBAL_WARN_LOG("filesystem: failed to open host file '{}'", host_path);
		return false;
	}

	const std::streamsize file_size = file.tellg();
	file.seekg(0, std::ios::beg);

	std::vector<std::uint8_t> buffer(static_cast<std::size_t>(file_size));
	file.read(reinterpret_cast<char*>(buffer.data()), file_size);

	list_[virtual_path] = std::make_shared<file_t>(std::move(buffer));

	GLOBAL_LOG("filesystem: loaded '{}' -> '{}' ({} bytes)", host_path, virtual_path, file_size);

	return true;
}

static std::string normalize_virtual_path(std::string path)
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

bool filesystem_t::load_directory_at(const std::string& host_path, const path_type& virtual_path)
{
	std::error_code ec;

	const std::filesystem::path host_root(host_path);

	if (!std::filesystem::is_directory(host_root, ec))
	{
		GLOBAL_WARN_LOG("filesystem: host directory '{}' not found", host_path);
		return false;
	}

	const auto base = normalize_virtual_path(virtual_path);

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

		auto child = base.empty() ? normalize_virtual_path(relative.string())
			: base + "/" + normalize_virtual_path(relative.string());

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