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

class filesystem_t
{
public:
	using path_type = std::string;

	filesystem_t() = default;

	[[nodiscard]] std::shared_ptr<file_t> open_at(const path_type& path);
	[[nodiscard]] std::shared_ptr<file_t> create_at(const path_type& path);

	bool load_at(const std::string& host_path, const path_type& virtual_path);

	[[nodiscard]] bool delete_at(const path_type& path);
	[[nodiscard]] bool exists(const path_type& path) const;

protected:
	std::unordered_map<path_type, std::shared_ptr<file_t>> list_;
};
