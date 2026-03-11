#include "filesystem.hpp"

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

std::span<const std::uint8_t> file_handle_t::read() const
{
	if (!is_open() || !can_read())
	{
		return { };
	}

	return object_->read();
}

bool file_handle_t::write(const std::span<const std::uint8_t> buffer) const
{
	if (!is_open() || !can_write())
	{
		return false;
	}

	object_->write(buffer);

	return true;
}

bool file_handle_t::can_read() const noexcept
{
	return (access_ & access_read) != 0;
}

bool file_handle_t::can_write() const noexcept
{
	return (access_ & access_write) != 0;
}

bool file_handle_t::is_open() const noexcept
{
	return object_ != nullptr;
}

file_handle_t::id_type file_handle_t::id() const noexcept
{
	return id_;
}

std::shared_ptr<file_handle_t> filesystem_t::open_at(const path_type& path, const access_type access)
{
	const auto it = list_.find(path);

	if (it == std::end(list_))
	{
		return { };
	}

	return create_file_handle(it->second, access);
}

std::shared_ptr<file_handle_t> filesystem_t::create_at(const path_type& path, const access_type access)
{
	const auto file = std::make_shared<file_t>();

	list_[path] = file;

	return create_file_handle(file, access);
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

std::shared_ptr<file_handle_t> filesystem_t::find_handle(const file_handle_t::id_type handle_id) const
{
	const auto it = handles_.find(handle_id);

	if (it == std::end(handles_))
	{
		return { };
	}

	return it->second;
}

bool filesystem_t::close_handle(const file_handle_t::id_type handle_id)
{
	const auto it = handles_.find(handle_id);

	if (it == std::end(handles_))
	{
		return false;
	}

	handles_.erase(it);

	return true;
}

std::shared_ptr<file_handle_t> filesystem_t::create_file_handle(std::shared_ptr<file_t> file, access_type access)
{
	const file_handle_t::id_type handle_id = allocate_handle_id();

	const auto handle = std::make_shared<file_handle_t>(std::move(file), access, handle_id);

	handles_[handle_id] = handle;

	return handle;
}

file_handle_t::id_type filesystem_t::allocate_handle_id()
{
	const file_handle_t::id_type id = free_handle_id_;

	free_handle_id_ += file_handle_t::id_increment;

	return id;
}
