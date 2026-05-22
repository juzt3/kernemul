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
}
