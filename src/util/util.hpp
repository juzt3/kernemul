#pragma once
#include <random>
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

	template <typename T>
	T generate_random(T min_value, T max_value)
	{
		static std::mt19937_64 engine(std::random_device{}());

		std::uniform_int_distribution<T> distribution(min_value, max_value);

		return distribution(engine);
	}
}
