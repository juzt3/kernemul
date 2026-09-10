#pragma once
#include "linked_list.hpp"
#include "types.hpp"

using loaded_module_list_t = win_linked_list<
	_KLDR_DATA_TABLE_ENTRY,
	offsetof(_KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks)
>;

using active_process_list_t = win_linked_list<
	_EPROCESS,
	offsetof(_EPROCESS, ActiveProcessLinks)
>;
