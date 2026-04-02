#include "filesystem.hpp"

#include <fstream>
#include "../util/logs.hpp"

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

std::shared_ptr<file_t> filesystem_t::open_at(const path_type& path)
{
	const auto it = list_.find(path);

	if (it == std::end(list_))
	{
		return {};
	}

	return it->second;
}

std::shared_ptr<file_t> filesystem_t::create_at(const path_type& path)
{
	const auto file = std::make_shared<file_t>();

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
