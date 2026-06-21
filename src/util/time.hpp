#pragma once

#include <chrono>
#include <cstdint>

namespace util
{
	constexpr std::uint64_t filetime_unix_epoch_offset = 116444736000000000ULL;

	inline std::uint64_t filetime_now()
	{
		const auto now = std::chrono::system_clock::now();
		const auto since_epoch = now.time_since_epoch();
		const auto hundreds_of_ns = std::chrono::duration_cast<std::chrono::duration<std::uint64_t, std::ratio<1, 10'000'000>>>(since_epoch);
		return hundreds_of_ns.count() + filetime_unix_epoch_offset;
	}

	inline std::int64_t performance_counter()
	{
		const auto now = std::chrono::high_resolution_clock::now();
		return now.time_since_epoch().count();
	}

	inline std::int64_t performance_frequency()
	{
		using period = std::chrono::high_resolution_clock::period;
		return static_cast<std::int64_t>(period::den / period::num);
	}
}
