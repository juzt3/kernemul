#pragma once
#include <spdlog/spdlog.h>

#define LOG(fmt, ...) spdlog::info(fmt __VA_OPT__(,) __VA_ARGS__)
#define WARN(fmt, ...) spdlog::warn(fmt __VA_OPT__(,) __VA_ARGS__)
#define ERR(fmt, ...) spdlog::error(fmt __VA_OPT__(,) __VA_ARGS__)
