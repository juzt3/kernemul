#pragma once

struct win_kernel_state;
struct proc_module;

namespace modules
{
	// Every handler ntoskrnl's exports are redirected to, one module per area of the kernel.
	void register_ntoskrnl(win_kernel_state& state, proc_module& mod);

	// The globals ntoskrnl's own initialisers never ran to fill in. Deliberately not one of the
	// registrars above, because it runs later: a registrar fires from inside map_redirect_module,
	// before the constructor has a KUSER_SHARED_DATA or a System EPROCESS to read.
	void init_ntoskrnl_globals(win_kernel_state& state, proc_module& mod);
}
