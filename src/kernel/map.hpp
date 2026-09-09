#pragma once
#include <pe.hpp>

struct addr_space;
class process;

namespace krnl
{
	bool map_img(process& proc, const pe::image* img, bool supervisor);
}
