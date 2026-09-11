#include "nt_thread_ops.hpp"
#include "../win_kernel.hpp"
#include "../status.hpp"
#include "../../../util/log.hpp"

void modules::register_ntoskrnl_thread_ops(win_kernel_state& state, proc_module& mod)
{
	auto* sys_proc = state.sys_proc.get();

	state.redirect(mod, "PsCreateSystemThread",
		[sys_proc](vcpu& cpu, addr_t thread_handle_out, std::uint32_t /*desired_access*/,
			addr_t /*object_attributes*/, std::uint64_t /*process_handle*/,
			addr_t client_id_out, addr_t start_routine, addr_t start_context) -> NTSTATUS
		{
			LOG_INFO("PsCreateSystemThread(handle_out=0x{:X}, start=0x{:X}, ctx=0x{:X})",
				thread_handle_out, start_routine, start_context);

			auto t = sys_proc->create_thread(cpu, start_routine);
			cpu.emu()->call_conv()->set_arg(cpu, *t, 0, start_context);

			const auto tid = static_cast<std::uint64_t>(t->id());

			if (thread_handle_out)
				cpu.write_virt_mem(thread_handle_out, tid);

			if (client_id_out)
			{
				const std::uint64_t cid[2] = {
					static_cast<std::uint64_t>(sys_proc->id()),
					tid
				};
				cpu.write_virt_mem(client_id_out, cid, sizeof(cid));
			}

			LOG_INFO("PsCreateSystemThread: created tid={}", tid);
			return STATUS_SUCCESS;
		});
}
