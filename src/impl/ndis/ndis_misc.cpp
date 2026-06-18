#include "ndis_misc.hpp"

static void handle_register_filter_driver(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type driver_object, emulator_t::address_type filter_driver_characteristics,
	emulator_t::address_type driver_context, emulator_t::address_type filter_driver_handle_out)
{
	THREAD_LOG("NdisFRegisterFilterDriver called (driver=0x{:X}, characteristics=0x{:X}, context=0x{:X}, handle_out=0x{:X})",
		driver_object, filter_driver_characteristics, driver_context, filter_driver_handle_out);

	if (filter_driver_handle_out)
	{
		const auto fake_handle = emulator->heap_allocate(0x100, prot_read_write, true);
		auto error = fake_handle.error_or({});
		error.throw_if("NdisFRegisterFilterDriver: allocate fake handle");

		error = emulator->write_virtual_memory(filter_driver_handle_out, &fake_handle.value(), sizeof(fake_handle.value()));
		error.throw_if("NdisFRegisterFilterDriver: write handle");
	}

	write_nt_success(emulator);
}

static void handle_deregister_filter_driver(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type filter_driver_handle)
{
	THREAD_LOG("NdisFDeregisterFilterDriver called (handle=0x{:X})", filter_driver_handle);
}

void redirect_ndis_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_register_filter_driver>(emulator, mapped_image, "NdisFRegisterFilterDriver");
	redirect_handler<handle_deregister_filter_driver>(emulator, mapped_image, "NdisFDeregisterFilterDriver");
}
