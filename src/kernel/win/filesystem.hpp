#pragma once
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

class win_file
{
public:
	win_file() = default;
	explicit win_file(std::vector<std::uint8_t> data) : data_(std::move(data)) {}

	[[nodiscard]] std::span<const std::uint8_t> data() const { return data_; }
	[[nodiscard]] std::span<std::uint8_t> data() { return data_; }
	[[nodiscard]] std::size_t size() const noexcept { return data_.size(); }

	void write(std::span<const std::uint8_t> buf);
	void write(const void* buf, std::size_t size);

private:
	std::vector<std::uint8_t> data_;
};

class win_filesystem
{
public:
	struct dir_entry
	{
		std::string name;
		bool is_directory = false;
		std::uint64_t size = 0;
	};

	[[nodiscard]] std::shared_ptr<win_file> open(std::string_view path) const;
	std::shared_ptr<win_file> create(std::string_view path);
	bool remove(std::string_view path);
	[[nodiscard]] bool exists(std::string_view path) const;
	[[nodiscard]] bool dir_exists(std::string_view path) const;

	[[nodiscard]] std::vector<dir_entry> list_dir(std::string_view path) const;

	bool load_file(const std::filesystem::path& host_path, std::string_view virtual_path);
	bool load_dir(const std::filesystem::path& host_dir, std::string_view virtual_path);

	[[nodiscard]] static std::string normalize(std::string_view path);

private:
	std::unordered_map<std::string, std::shared_ptr<win_file>> files_;
};
