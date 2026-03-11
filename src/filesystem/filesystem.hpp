#pragma once
#include <unordered_map>
#include <memory>
#include <string>
#include <span>

class file_t
{
public:
	file_t() = default;

	explicit file_t(std::vector<std::uint8_t> buffer)
			:	buffer_(std::move(buffer)) { }

	[[nodiscard]] std::span<const std::uint8_t> read() const;

	void write(std::span<const std::uint8_t> buffer);

	[[nodiscard]] std::size_t size() const noexcept;

	[[nodiscard]] std::span<std::uint8_t> buffer();
	[[nodiscard]] std::span<const std::uint8_t> buffer() const;

protected:
	std::vector<std::uint8_t> buffer_;
};

class file_handle_t
{
public:
	using id_type = std::uint32_t;

	constexpr static id_type id_increment = sizeof(id_type);

	enum access_type : std::uint8_t
	{
		access_none = 0,
		access_read = 1,
		access_write = 2
	};

	file_handle_t() = default;

	explicit file_handle_t(std::shared_ptr<file_t> object, const access_type access, const id_type id)
			:	object_(std::move(object)),
				access_(access),
				id_(id) { }

	[[nodiscard]] std::span<const std::uint8_t> read() const;
	[[nodiscard]] bool write(std::span<const std::uint8_t> buffer) const;

	[[nodiscard]] bool can_read() const noexcept;
	[[nodiscard]] bool can_write() const noexcept;

	[[nodiscard]] bool is_open() const noexcept;

	[[nodiscard]] id_type id() const noexcept;

protected:
	std::shared_ptr<file_t> object_;
	access_type access_ = access_none;
	id_type id_ = 0;
};

class filesystem_t
{
public:
	using path_type = std::string;
	using buffer_type = std::string;
	using access_type = file_handle_t::access_type;

	filesystem_t() = default;

	[[nodiscard]] std::shared_ptr<file_handle_t> open_at(const path_type& path, access_type access = access_type::access_read);
	[[nodiscard]] std::shared_ptr<file_handle_t> create_at(const path_type& path, access_type access = access_type::access_read);

	[[nodiscard]] bool delete_at(const path_type& path);

	[[nodiscard]] std::shared_ptr<file_handle_t> find_handle(file_handle_t::id_type handle_id) const;
	[[nodiscard]] bool close_handle(file_handle_t::id_type handle_id);

protected:
	[[nodiscard]] std::shared_ptr<file_handle_t> create_file_handle(std::shared_ptr<file_t> file, access_type access);
	[[nodiscard]] file_handle_t::id_type allocate_handle_id();

	std::unordered_map<path_type, std::shared_ptr<file_t>> list_;
	std::unordered_map<file_handle_t::id_type, std::shared_ptr<file_handle_t>> handles_;

	file_handle_t::id_type free_handle_id_ = file_handle_t::id_increment;
};
