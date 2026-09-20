#pragma once

struct win_kernel_state;
struct proc_module;
struct addr_space;

namespace modules
{
	// Every handler ntoskrnl's exports are redirected to, one module per area of the kernel.
	void register_ntoskrnl(win_kernel_state& state, proc_module& mod);

	// The globals ntoskrnl's own initialisers never ran to fill in. Deliberately not one of the
	// registrars above, because it runs later: a registrar fires from inside map_redirect_module,
	// before the constructor has a KUSER_SHARED_DATA or a System EPROCESS to read.
	void init_ntoskrnl_globals(win_kernel_state& state, proc_module& mod);

	// Describes every frame the tables currently hand out. Mappings made after the globals are
	// set up -- an image loaded later, a pool block -- need this again to be described.
	// Before anything maps: from here the mmu describes each page as it maps it.
	void init_pfn_database(addr_space& space);
}
