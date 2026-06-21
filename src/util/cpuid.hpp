#pragma once

#include <array>
#include <cstdint>

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#endif

inline std::array<std::int32_t, 4> host_cpuid(const std::int32_t leaf, const std::int32_t subleaf)
{
	std::array<std::int32_t, 4> regs{};

#if defined(_MSC_VER)
	__cpuidex(regs.data(), leaf, subleaf);
#elif defined(__GNUC__) || defined(__clang__)
	__cpuid_count(leaf, subleaf, regs[0], regs[1], regs[2], regs[3]);
#else
	#error "Unsupported compiler for CPUID"
#endif

	return regs;
}
