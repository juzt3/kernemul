#pragma once
#include "linked_list.hpp"

struct ldr_data_table_entry
{
	list_entry in_load_order_links;
	addr_t dll_base;
	addr_t entry_point;
	std::uint32_t size_of_image;
};

using loaded_module_list_t = win_linked_list<
	ldr_data_table_entry,
	offsetof(ldr_data_table_entry, in_load_order_links)
>;
