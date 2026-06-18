#include "tdi_misc.hpp"

void redirect_tdi_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			const auto binding_info = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto info_size = emulator->read_register<x86::reg::rdx, std::uint64_t>();
			const auto binding_handle_out = emulator->read_register<x86::reg::r8, emulator_t::address_type>();

			THREAD_LOG("TdiRegisterPnPHandlers called (binding_info=0x{:X}, handle_out=0x{:X})", binding_info, binding_handle_out);

			if (binding_handle_out)
			{
				const auto handle = kernel::object_manager->allocate_id();
				emulator_err_t error = emulator->write_virtual_memory(binding_handle_out, &handle, sizeof(handle));
				error.throw_if("TdiRegisterPnPHandlers: write handle");
			}

			write_nt_success(emulator);
		},
		mapped_image,
		"TdiRegisterPnPHandlers"
	);

	redirect_function(
		[emulator]
		{
			const auto handle = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();

			THREAD_LOG("TdiDeregisterNotificationHandler called (handle=0x{:X})", handle);

			write_nt_success(emulator);
		},
		mapped_image,
		"TdiDeregisterNotificationHandler"
	);
}
