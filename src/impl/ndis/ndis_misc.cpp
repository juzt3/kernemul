#include "ndis_misc.hpp"

void redirect_ndis_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			const auto driver_object = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto filter_driver_characteristics = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();
			const auto driver_context = emulator->read_register<x86::reg::r8, emulator_t::address_type>();
			const auto filter_driver_handle_out = emulator->read_register<x86::reg::r9, emulator_t::address_type>();

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
		},
		mapped_image,
		"NdisFRegisterFilterDriver"
	);

	redirect_function(
		[emulator]
		{
			const auto filter_driver_handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("NdisFDeregisterFilterDriver called (handle=0x{:X})", filter_driver_handle);
		},
		mapped_image,
		"NdisFDeregisterFilterDriver"
	);
}
