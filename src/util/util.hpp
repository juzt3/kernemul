#pragma once
#include <string>

namespace util
{
	inline std::string narrow_wstring(const std::wstring_view wide)
	{
		std::string result;
		result.reserve(wide.size());

		for (const auto wc : wide)
		{
			result += static_cast<char>(wc & 0xFF);
		}

		return result;
	}
}
