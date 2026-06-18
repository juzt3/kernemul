#include "tdi_misc.hpp"

static void handle_register_pnp_handlers(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type binding_info, std::uint64_t info_size,
	emulator_t::address_type binding_handle_out)
{
	THREAD_LOG("TdiRegisterPnPHandlers called (binding_info=0x{:X}, handle_out=0x{:X})", binding_info, binding_handle_out);

	if (binding_handle_out)
	{
		const auto handle = kernel::object_manager->allocate_id();
		emulator_err_t error = emulator->write_virtual_memory(binding_handle_out, &handle, sizeof(handle));
		error.throw_if("TdiRegisterPnPHandlers: write handle");
	}

	write_nt_success(emulator);
}

static void handle_deregister_notification_handler(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type handle)
{
	THREAD_LOG("TdiDeregisterNotificationHandler called (handle=0x{:X})", handle);

	write_nt_success(emulator);
}

void redirect_tdi_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_register_pnp_handlers>(emulator, mapped_image, "TdiRegisterPnPHandlers");
	redirect_handler<handle_deregister_notification_handler>(emulator, mapped_image, "TdiDeregisterNotificationHandler");
}
