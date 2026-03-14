#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace pdb
{
	struct cv_guid_t
	{
		std::uint32_t data1;
		std::uint16_t data2;
		std::uint16_t data3;
		std::uint8_t data4[8];
	};

	static_assert(sizeof(cv_guid_t) == 16, "cv_guid_t size mismatch");

	struct cv_info_pdb70_t
	{
		std::uint32_t cv_signature;
		cv_guid_t guid;
		std::uint32_t age;
		char pdb_file_name[1];
	};

	[[nodiscard]] const cv_info_pdb70_t* extract_cv_info(const void* image_base);

	[[nodiscard]] std::string format_symbol_hash(const cv_info_pdb70_t& cv_info);

	[[nodiscard]] std::string build_symbol_url(std::string_view pdb_name, std::string_view hash);

	[[nodiscard]] std::vector<std::uint8_t> download_pdb(
		std::string_view pdb_name,
		const cv_info_pdb70_t& cv_info);

	[[nodiscard]] std::vector<std::uint8_t> download_pdb_for_image(
		std::string_view image_path);
}
