#include "ndis.hpp"
#include "../win_kernel.hpp"
#include "../objects.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"
#include <vector>

namespace
{

// The filter driver registration, kept so deregistering it has something to
// find. Nothing here has a network adapter to attach a filter to, so what a
// filter driver gets is the handle and nothing to filter.
struct ndis_filter_host final : win_object
{
	addr_t driver_object = 0;
};

constexpr std::size_t filter_driver_body_size = 0x40;

}

// NDIS, as far as a filter driver gets before it waits for a packet. There is
// no adapter here and no packet path, so registering a filter driver succeeds
// and nothing is ever sent through it.
void modules::register_ndis(win_kernel_state& state, proc_module& mod)
{
	auto* st = &state;

	state.redirect(mod, "NdisFRegisterFilterDriver",
		[st](vcpu& cpu, const addr_t driver_object, const addr_t driver_context,
			emu_object<void> characteristics, emu_object<addr_t> filter_driver_handle) -> NTSTATUS
		{
			if (!filter_driver_handle || !characteristics)
				return STATUS_INVALID_PARAMETER;

			// NDIS_FILTER_DRIVER_CHARACTERISTICS opens with an NDIS_OBJECT_HEADER
			// -- Type, Revision, Size -- then the NDIS version the driver was
			// built against, which is the part worth reporting.
			auto& space = *cpu.curr_addr_space();
			const auto major = space.read_mem<std::uint8_t>(characteristics.address() + 4);
			const auto minor = space.read_mem<std::uint8_t>(characteristics.address() + 5);

			auto host = std::make_shared<ndis_filter_host>();
			host->driver_object = driver_object;

			const std::vector<std::uint8_t> body(filter_driver_body_size, 0);
			const auto addr = st->objs.create_object(0, body.data(), body.size(),
				std::move(host), prot_rw | prot_supervisor);

			if (!addr)
				return STATUS_INSUFFICIENT_RESOURCES;

			filter_driver_handle.write(addr);

			THREAD_LOG_WARN("NdisFRegisterFilterDriver(driver=0x{:X}, context=0x{:X}, "
				"ndis {}.{}) -> 0x{:X}: there is no adapter here to attach a filter to",
				driver_object, driver_context, major, minor, addr);

			return STATUS_SUCCESS;
		});

	state.redirect(mod, "NdisFDeregisterFilterDriver",
		[st](vcpu&, const addr_t filter_driver_handle)
		{
			if (!st->objs.get_object<ndis_filter_host>(filter_driver_handle))
			{
				THREAD_LOG_WARN("NdisFDeregisterFilterDriver: 0x{:X} is not a filter driver",
					filter_driver_handle);
				return;
			}

			THREAD_LOG_INFO("NdisFDeregisterFilterDriver(0x{:X})", filter_driver_handle);

			st->objs.dereference_object(filter_driver_handle);
		});
}
