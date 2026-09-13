#pragma once
#include <spdlog/spdlog.h>
#include <cstdint>
#include <string_view>

#define LOG_INFO(fmt, ...) spdlog::info(fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_WARN(fmt, ...) spdlog::warn(fmt __VA_OPT__(,) __VA_ARGS__)
#define LOG_ERR(fmt, ...) spdlog::error(fmt __VA_OPT__(,) __VA_ARGS__)

class vcpu;

void set_log_cpu(vcpu* cpu);

std::uint32_t log_cpu_id();
std::uint32_t log_thread_id();
std::uint32_t log_process_id();
std::string_view log_mode();

#define THREAD_LOG_PREFIX     "[cpu={} tid={} pid={} {}] "
#define THREAD_LOG_PREFIX_ARGS log_cpu_id(), log_thread_id(), log_process_id(), log_mode()

#define THREAD_LOG_INFO(fmt, ...) \
	LOG_INFO(THREAD_LOG_PREFIX fmt, THREAD_LOG_PREFIX_ARGS __VA_OPT__(,) __VA_ARGS__)

#define THREAD_LOG_WARN(fmt, ...) \
	LOG_WARN(THREAD_LOG_PREFIX fmt, THREAD_LOG_PREFIX_ARGS __VA_OPT__(,) __VA_ARGS__)

#define THREAD_LOG_ERR(fmt, ...) \
	LOG_ERR(THREAD_LOG_PREFIX fmt, THREAD_LOG_PREFIX_ARGS __VA_OPT__(,) __VA_ARGS__)
