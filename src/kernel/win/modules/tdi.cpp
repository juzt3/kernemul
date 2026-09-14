#include "tdi.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../win_kernel.hpp"
#include "../../../util/log.hpp"

// There is no transport here, so the handlers a client registers are never
// called and the binding handle names nothing.
void modules::register_tdi(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "TdiRegisterPnPHandlers",
		[st](vcpu&, const addr_t binding_info, const std::uint64_t information_size,
			emu_object<addr_t> binding_handle) -> NTSTATUS
		{
			if (!binding_handle)
				return STATUS_INVALID_PARAMETER;

			const addr_t handle = st->objs.allocate_id();
			binding_handle.write(handle);

			THREAD_LOG_WARN("TdiRegisterPnPHandlers(info=0x{:X}/{}) -> 0x{:X}: there is no "
				"transport here to bind to", binding_info, information_size, handle);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "TdiDeregisterNotificationHandler",
		[](vcpu&, const addr_t binding_handle) -> NTSTATUS
		{
			THREAD_LOG_INFO("TdiDeregisterNotificationHandler(0x{:X})", binding_handle);

			return STATUS_SUCCESS;
		});
}
