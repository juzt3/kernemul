#pragma once
#include <pe.hpp>
#include <filesystem>
#include <memory>
#include <span>
#include <vector>

struct proc_module;
struct addr_space;
class process;

namespace krnl
{
	// The file laid out the way it is run, every section at its virtual address; empty if not a PE.
	std::vector<std::uint8_t> pe_virtual_image(std::span<const std::uint8_t> raw);

	std::shared_ptr<proc_module> map_img(process& proc, std::string_view name, const pe::image* img, bool supervisor, bool skip_imports = false);
	std::shared_ptr<proc_module> map_img(process& proc, const std::filesystem::path& path, bool supervisor, bool skip_imports = false);
	std::shared_ptr<proc_module> map_img(process& proc, std::string_view name, std::span<const std::uint8_t> raw, bool supervisor, bool skip_imports = false);
}
