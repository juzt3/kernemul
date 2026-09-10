#include "process.hpp"
#include "win_kernel.hpp"

void win_kernel_proc::module_add_cb(proc_module& mod)
{
	if (!kernel_.loaded_module_list.address())
		return;

	ldr_data_table_entry entry{};
	entry.dll_base = mod.addr;
	entry.entry_point = mod.entry_point;
	entry.size_of_image = mod.size;

	kernel_.loaded_module_list.push_back(entry);
}
