#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <optional>
#include <unordered_map>

namespace pdb
{
	struct symbol_t
	{
		std::string name;
		std::uint32_t rva = 0;
		std::uint32_t size = 0;
		std::uint16_t section = 0;
	};

	class pdb_file_t
	{
	public:
		explicit pdb_file_t(std::vector<std::uint8_t> data);

		pdb_file_t(pdb_file_t&&) noexcept = default;
		pdb_file_t& operator=(pdb_file_t&&) noexcept = default;

		pdb_file_t(const pdb_file_t&) = delete;
		pdb_file_t& operator=(const pdb_file_t&) = delete;

		[[nodiscard]] std::optional<symbol_t> find_symbol(std::string_view name) const;
		[[nodiscard]] std::optional<std::uint32_t> find_rva(std::string_view name) const;

		[[nodiscard]] std::span<symbol_t> symbols() noexcept;
		[[nodiscard]] std::span<const symbol_t> symbols() const noexcept;
		[[nodiscard]] std::size_t symbol_count() const noexcept;

	protected:
		void parse();

		std::vector<std::uint8_t> data_;
		std::vector<symbol_t> symbols_;
		std::unordered_map<std::string, std::size_t> name_to_index_;
	};

	[[nodiscard]] pdb_file_t load_pdb_from_file(std::string_view path);
	[[nodiscard]] pdb_file_t load_pdb_for_image(std::string_view image_path);
	[[nodiscard]] pdb_file_t load_pdb_for_image_buffer(const void* image_base);
}
