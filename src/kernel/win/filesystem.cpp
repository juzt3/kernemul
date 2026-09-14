#include "filesystem.hpp"
#include "../../util/file.hpp"
#include "../../util/log.hpp"

#include <filesystem>
#include <map>

void win_file::write(const std::span<const std::uint8_t> buf)
{
	data_.assign(buf.begin(), buf.end());
}

void win_file::write(const void* buf, const std::size_t size)
{
	data_.resize(size);
	if (buf && size > 0)
		std::memcpy(data_.data(), buf, size);
}

std::string win_filesystem::normalize(const std::string_view path)
{
	std::string result(path);

	for (auto& c : result)
	{
		if (c == '\\')
			c = '/';
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}

	while (!result.empty() && result.back() == '/')
		result.pop_back();

	// Guest paths are object manager names; everything here is named from the
	// drive letter down.
	for (const std::string_view prefix : { "/??/", "/dosdevices/" })
	{
		if (result.starts_with(prefix))
		{
			result.erase(0, prefix.size());
			break;
		}
	}

	return result;
}

std::shared_ptr<win_file> win_filesystem::open(const std::string_view path) const
{
	const auto it = files_.find(normalize(path));
	return it != files_.end() ? it->second : nullptr;
}

std::shared_ptr<win_file> win_filesystem::create(const std::string_view path)
{
	const auto norm = normalize(path);
	auto file = std::make_shared<win_file>();
	files_[norm] = file;
	return file;
}

bool win_filesystem::remove(const std::string_view path)
{
	const auto it = files_.find(normalize(path));
	if (it == files_.end())
		return false;

	if (it->second.use_count() > 1)
		return false;

	files_.erase(it);
	return true;
}

bool win_filesystem::exists(const std::string_view path) const
{
	return files_.contains(normalize(path));
}

bool win_filesystem::dir_exists(const std::string_view path) const
{
	const auto norm = normalize(path);

	if (norm.empty())
		return true;

	const auto prefix = norm + "/";

	for (const auto& [key, _] : files_)
	{
		if (key.starts_with(prefix))
			return true;
	}

	return false;
}

std::vector<win_filesystem::dir_entry> win_filesystem::list_dir(const std::string_view path) const
{
	auto prefix = normalize(path);
	if (!prefix.empty())
		prefix += '/';

	std::map<std::string, dir_entry> entries;

	for (const auto& [key, file] : files_)
	{
		if (!key.starts_with(prefix))
			continue;

		const auto rest = key.substr(prefix.size());
		if (rest.empty())
			continue;

		const auto slash = rest.find('/');

		if (slash == std::string::npos)
		{
			auto& e = entries[rest];
			e.name = rest;
			e.size = file ? file->size() : 0;
		}
		else
		{
			auto name = rest.substr(0, slash);
			auto& e = entries[name];
			e.name = std::move(name);
			e.is_directory = true;
		}
	}

	std::vector<dir_entry> result;
	result.reserve(entries.size());

	for (auto& [_, e] : entries)
		result.push_back(std::move(e));

	return result;
}

bool win_filesystem::load_file(const std::filesystem::path& host_path, const std::string_view virtual_path)
{
	auto buffer = util::read_file(host_path);
	if (buffer.empty() && std::filesystem::file_size(host_path) != 0)
	{
		LOG_WARN("filesystem: failed to read '{}'", host_path.string());
		return false;
	}

	const auto size = buffer.size();
	const auto norm = normalize(virtual_path);
	files_[norm] = std::make_shared<win_file>(std::move(buffer));

	LOG_INFO("filesystem: loaded '{}' -> '{}' ({} bytes)", host_path.string(), norm, size);
	return true;
}

bool win_filesystem::load_dir(const std::filesystem::path& host_dir, const std::string_view virtual_path)
{
	std::error_code ec;

	if (!std::filesystem::is_directory(host_dir, ec))
	{
		LOG_WARN("filesystem: '{}' is not a directory", host_dir.string());
		return false;
	}

	const auto base = normalize(virtual_path);
	std::size_t file_count = 0;

	for (auto it = std::filesystem::recursive_directory_iterator(
			host_dir, std::filesystem::directory_options::skip_permission_denied, ec);
		it != std::filesystem::recursive_directory_iterator(); it.increment(ec))
	{
		if (ec)
		{
			ec.clear();
			continue;
		}

		if (!it->is_regular_file(ec))
			continue;

		const auto relative = std::filesystem::relative(it->path(), host_dir, ec);
		if (ec)
		{
			ec.clear();
			continue;
		}

		auto child = base.empty()
			? normalize(relative.string())
			: base + "/" + normalize(relative.string());

		if (load_file(it->path(), child))
			++file_count;
	}

	LOG_INFO("filesystem: loaded directory '{}' -> '{}' ({} files)", host_dir.string(), base, file_count);
	return true;
}
