#include "tbs.hpp"
#include "../types.hpp"
#include "../win_kernel.hpp"
#include "../../../util/log.hpp"
#include <cstdint>

namespace
{

constexpr std::uint32_t tbs_success = 0;
constexpr std::uint32_t tbs_e_buffer_too_small = 0x80284002;
constexpr std::uint32_t tbs_e_service_not_running = 0x80284008;

#pragma pack(push, 4)
struct tpm_device_info_t
{
	std::uint32_t struct_version;
	std::uint32_t tpm_version;
	std::uint32_t tpm_interface_type;
	std::uint32_t tpm_impl_revision;
};
#pragma pack(pop)

static_assert(sizeof(tpm_device_info_t) == 0x10);

}

// There is a TPM to describe but no service to talk to it through.
void modules::register_tbs(win_kernel_state& state, proc_module& mod)
{
	state.redirect(mod, "Tbsi_GetDeviceInfo",
		[](vcpu& cpu, const std::uint32_t size, const addr_t info) -> std::uint32_t
		{
			if (size < sizeof(tpm_device_info_t) || !info)
			{
				THREAD_LOG_WARN("Tbsi_GetDeviceInfo(size={}): needs {}",
					size, sizeof(tpm_device_info_t));

				return tbs_e_buffer_too_small;
			}

			tpm_device_info_t device{};
			device.struct_version = 2;
			device.tpm_version = 2;

			emu_object<tpm_device_info_t>(*cpu.curr_addr_space(), info).write(device);

			THREAD_LOG_INFO("Tbsi_GetDeviceInfo(0x{:X}) -> tpm 2.0", info);

			return tbs_success;
		});

	state.redirect(mod, "Tbsi_Context_Create",
		[](vcpu&, const addr_t context_params, const addr_t context_handle) -> std::uint32_t
		{
			THREAD_LOG_WARN("Tbsi_Context_Create(params=0x{:X}, handle_out=0x{:X}): nothing here "
				"runs the TPM base services", context_params, context_handle);

			return tbs_e_service_not_running;
		});
}
