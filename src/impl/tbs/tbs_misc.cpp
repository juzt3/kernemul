#include "tbs_misc.hpp"

void redirect_tbs_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const kernel_image_t& mapped_image)
{
	redirect_function(
		[emulator]
		{
			const auto size = emulator->read_register<x86::reg::rcx, std::uint32_t>();
			const auto info_address = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			struct tpm_device_info_t
			{
				std::uint32_t struct_version;
				std::uint32_t tpm_version;
				std::uint32_t tpm_interface_type;
				std::uint32_t tpm_imp_revision;
			};

			if (size < sizeof(tpm_device_info_t))
			{
				THREAD_WARN_LOG("Tbsi_GetDeviceInfo called with insufficient size (size={}, needed={})",
					size, sizeof(tpm_device_info_t));

				write_return_value(emulator, 0x80284002);

				return;
			}

			tpm_device_info_t info = {};
			info.struct_version = 2;
			info.tpm_version = 2;
			info.tpm_interface_type = 0;
			info.tpm_imp_revision = 0;

			emulator_err_t error = emulator->write_virtual_memory(info_address, &info, sizeof(info));
			error.throw_if("Tbsi_GetDeviceInfo: write TPM_DEVICE_INFO");

			THREAD_LOG("Tbsi_GetDeviceInfo called (size={}, info=0x{:X}) -> success", size, info_address);

			write_return_value(emulator, 0);
		},
		mapped_image,
		"Tbsi_GetDeviceInfo"
	);

	redirect_function(
		[emulator]
		{
			const auto context_params = emulator->read_register<x86::reg::rcx, emulator_t::address_type>();
			const auto context_handle_out = emulator->read_register<x86::reg::rdx, emulator_t::address_type>();

			THREAD_LOG("Tbsi_Context_Create called (params=0x{:X}, handle_out=0x{:X}) -> TBS_E_SERVICE_NOT_RUNNING",
				context_params, context_handle_out);

			constexpr std::uint32_t tbs_e_service_not_running = 0x80284008;
			write_return_value(emulator, tbs_e_service_not_running);
		},
		mapped_image,
		"Tbsi_Context_Create"
	);
}
