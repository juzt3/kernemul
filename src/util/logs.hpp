#pragma once
#include <spdlog/spdlog.h>

namespace kernel
{
	std::uint64_t current_thread_id(); // thread_t::id_type
}

#define THREAD_LOG(fmt, ...) spdlog::info("[thread id={}] " fmt, kernel::current_thread_id() __VA_OPT__(,) __VA_ARGS__)
#define THREAD_WARN_LOG(fmt, ...) spdlog::warn("[thread id={}] " fmt, kernel::current_thread_id() __VA_OPT__(,) __VA_ARGS__)
#define THREAD_ERR_LOG(fmt, ...) spdlog::error("[thread id={}] " fmt, kernel::current_thread_id() __VA_OPT__(,) __VA_ARGS__)

#define GLOBAL_LOG(fmt, ...) spdlog::info(fmt __VA_OPT__(,) __VA_ARGS__)
#define GLOBAL_WARN_LOG(fmt, ...) spdlog::warn(fmt __VA_OPT__(,) __VA_ARGS__)
#define GLOBAL_ERR_LOG(fmt, ...) spdlog::error(fmt __VA_OPT__(,) __VA_ARGS__)
