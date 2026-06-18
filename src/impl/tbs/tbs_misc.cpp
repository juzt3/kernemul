#include "tbs_misc.hpp"

struct tpm_device_info_t
{
	std::uint32_t struct_version;
	std::uint32_t tpm_version;
	std::uint32_t tpm_interface_type;
	std::uint32_t tpm_imp_revision;
};

static void handle_get_device_info(const std::shared_ptr<emulator_t>& emulator,
	std::uint32_t size, emulator_t::address_type info_address)
{
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
}

static void handle_context_create(const std::shared_ptr<emulator_t>& emulator,
	emulator_t::address_type context_params, emulator_t::address_type context_handle_out)
{
	THREAD_LOG("Tbsi_Context_Create called (params=0x{:X}, handle_out=0x{:X}) -> TBS_E_SERVICE_NOT_RUNNING",
		context_params, context_handle_out);

	constexpr std::uint32_t tbs_e_service_not_running = 0x80284008;
	write_return_value(emulator, tbs_e_service_not_running);
}

void redirect_tbs_misc_functions(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image)
{
	redirect_handler<handle_get_device_info>(emulator, mapped_image, "Tbsi_GetDeviceInfo");
	redirect_handler<handle_context_create>(emulator, mapped_image, "Tbsi_Context_Create");
}
