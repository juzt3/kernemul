#pragma once
#include <pe.hpp>

struct addr_space;

namespace krnl
{
	bool map_img(const pe::image* img, addr_space& space, bool supervisor);
}
