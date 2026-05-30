#pragma once
#include <unordered_map>
#include <memory>
#include <string>
#include <span>
#include <vector>
#include <cstdint>

class file_t
{
public:
	struct directory_tag_t { };
	static constexpr directory_tag_t directory_tag{ };

	file_t() = default;

	explicit file_t(std::vector<std::uint8_t> buffer)
			:	buffer_(std::move(buffer)) { }

	explicit file_t(directory_tag_t)
			:	is_directory_(true) { }

	[[nodiscard]] std::span<const std::uint8_t> read() const;

	void write(std::span<const std::uint8_t> buffer);

	[[nodiscard]] std::size_t size() const noexcept;

	[[nodiscard]] std::span<std::uint8_t> buffer();
	[[nodiscard]] std::span<const std::uint8_t> buffer() const;

	[[nodiscard]] bool is_directory() const noexcept;

protected:
	std::vector<std::uint8_t> buffer_;
	bool is_directory_ = false;
};

class filesystem_t
{
public:
	using path_type = std::string;

	filesystem_t() = default;

	[[nodiscard]] std::shared_ptr<file_t> open_at(const path_type& path);
	[[nodiscard]] std::shared_ptr<file_t> open_directory_at(const path_type& path);
	[[nodiscard]] std::shared_ptr<file_t> create_at(const path_type& path);
	[[nodiscard]] std::shared_ptr<file_t> create_directory_at(const path_type& path);

	bool load_at(const std::string& host_path, const path_type& virtual_path);
	bool load_directory_at(const std::string& host_path, const path_type& virtual_path);

	[[nodiscard]] bool delete_at(const path_type& path);
	[[nodiscard]] bool exists(const path_type& path) const;
	[[nodiscard]] bool directory_exists(const path_type& path) const;

	struct directory_entry_t
	{
		std::string name;
		bool is_directory = false;
		std::uint64_t size = 0;
	};

	[[nodiscard]] std::vector<directory_entry_t> list_directory(const path_type& path) const;

protected:
	[[nodiscard]] static path_type normalize(path_type path);

	std::unordered_map<path_type, std::shared_ptr<file_t>> list_;
};
