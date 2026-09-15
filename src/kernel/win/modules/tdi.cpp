#include "tdi.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../win_kernel.hpp"
#include "../../../util/log.hpp"
#include <cstdint>

namespace
{

// What the real TdiRegisterPnPHandlers answers, out of tdi.sys: neither code is in a header.
constexpr NTSTATUS tdi_bad_version = 0xC0010004;
constexpr NTSTATUS tdi_bad_size = 0xC0010005;

constexpr std::uint8_t maximum_tdi_version = 2;
constexpr std::uint32_t minimum_interface_info_size = 0x38;

}

void modules::register_tdi(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "TdiRegisterPnPHandlers",
		[st](vcpu&, emu_object<std::uint8_t> client_interface_info,
			const std::uint32_t interface_info_size,
			emu_object<addr_t> binding_handle) -> NTSTATUS
		{
			const auto version = client_interface_info.read();

			if (version > maximum_tdi_version)
			{
				THREAD_LOG_WARN("TdiRegisterPnPHandlers: tdi version {} is past {}",
					version, maximum_tdi_version);

				return tdi_bad_version;
			}

			if (interface_info_size < minimum_interface_info_size)
			{
				THREAD_LOG_WARN("TdiRegisterPnPHandlers: interface info is {} bytes, needs {}",
					interface_info_size, minimum_interface_info_size);

				return tdi_bad_size;
			}

			const addr_t handle = st->objs.allocate_id();
			binding_handle.write(handle);

			THREAD_LOG_WARN("TdiRegisterPnPHandlers(info=0x{:X}/{}, tdi {}) -> 0x{:X}: there is "
				"no transport here to bind to", client_interface_info.address(),
				interface_info_size, version, handle);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "TdiDeregisterNotificationHandler",
		[](vcpu&, const addr_t binding_handle) -> NTSTATUS
		{
			THREAD_LOG_INFO("TdiDeregisterNotificationHandler(0x{:X})", binding_handle);

			return STATUS_SUCCESS;
		});
}
