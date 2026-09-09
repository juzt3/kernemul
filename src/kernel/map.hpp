#pragma once
#include <pe.hpp>

struct addr_space;
class process;

namespace krnl
{
	bool map_img(process& proc, std::string_view name, const pe::image* img, bool supervisor);
}
