#pragma once
#include "linked_list.hpp"
#include <cstring>

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

struct eprocess
{
	std::uint8_t pad_0[0x440];
	addr_t unique_process_id;                  // +0x440
	list_entry active_process_links;           // +0x448
	std::uint8_t pad_1[0x5a8 - 0x458];
	std::uint8_t image_file_name[15];          // +0x5a8
};

using active_process_list_t = win_linked_list<
	eprocess,
	offsetof(eprocess, active_process_links)
>;
