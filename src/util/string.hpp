#pragma once
#include <string_view>

struct string_view_hash
{
	using is_transparent = void;
	size_t operator()(std::string_view s) const { return std::hash<std::string_view>{}(s); }
};
