#pragma once
#include <spdlog/spdlog.h>

namespace kernel
{
	std::uint64_t current_thread_id();
	std::uint64_t current_process_id();
	const char* current_mode_string();
}

#define THREAD_LOG(fmt, ...) spdlog::info("[tid={} pid={} {}] " fmt, kernel::current_thread_id(), kernel::current_process_id(), kernel::current_mode_string() __VA_OPT__(,) __VA_ARGS__)
#define THREAD_WARN_LOG(fmt, ...) spdlog::warn("[tid={} pid={} {}] " fmt, kernel::current_thread_id(), kernel::current_process_id(), kernel::current_mode_string() __VA_OPT__(,) __VA_ARGS__)
#define THREAD_ERR_LOG(fmt, ...) spdlog::error("[tid={} pid={} {}] " fmt, kernel::current_thread_id(), kernel::current_process_id(), kernel::current_mode_string() __VA_OPT__(,) __VA_ARGS__)

#define GLOBAL_LOG(fmt, ...) spdlog::info(fmt __VA_OPT__(,) __VA_ARGS__)
#define GLOBAL_WARN_LOG(fmt, ...) spdlog::warn(fmt __VA_OPT__(,) __VA_ARGS__)
#define GLOBAL_ERR_LOG(fmt, ...) spdlog::error(fmt __VA_OPT__(,) __VA_ARGS__)
