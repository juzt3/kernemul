#pragma once
#include <pe.hpp>
#include <filesystem>
#include <memory>
#include <span>

struct proc_module;
struct addr_space;
class process;

namespace krnl
{
	std::shared_ptr<proc_module> map_img(process& proc, std::string_view name, const pe::image* img, bool supervisor, bool skip_imports = false);
	std::shared_ptr<proc_module> map_img(process& proc, const std::filesystem::path& path, bool supervisor, bool skip_imports = false);
	std::shared_ptr<proc_module> map_img(process& proc, std::string_view name, std::span<const std::uint8_t> raw, bool supervisor, bool skip_imports = false);
}
