#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

namespace util
{
	inline std::vector<std::uint8_t> read_file(const std::filesystem::path& path)
	{
		std::ifstream file(path, std::ios::binary | std::ios::ate);

		if (!file.is_open())
		{
			return {};
		}

		const auto file_size = file.tellg();
		file.seekg(0, std::ios::beg);

		std::vector<std::uint8_t> data(static_cast<std::size_t>(file_size));
		file.read(reinterpret_cast<char*>(data.data()), file_size);

		return data;
	}
}
