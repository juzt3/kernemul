#include "nt_thread_ops.hpp"
#include "../win_kernel.hpp"
#include "../status.hpp"
#include "../types.hpp"
#include "../../../util/log.hpp"

void modules::register_ntoskrnl_thread_ops(win_kernel_state& state, proc_module& mod)
{
	auto* sys_proc = state.sys_proc.get();

	state.redirect(mod, "PsCreateSystemThread",
		[sys_proc, &objs = state.objs](vcpu& cpu, emu_object<std::uint64_t> thread_handle_out,
			[[maybe_unused]] std::uint32_t desired_access,
			[[maybe_unused]] emu_object<void> object_attributes, [[maybe_unused]] std::uint64_t process_handle,
			emu_object<CLIENT_ID> client_id_out, addr_t start_routine, addr_t start_context) -> NTSTATUS
		{
			LOG_INFO("PsCreateSystemThread(handle_out=0x{:X}, start=0x{:X}, ctx=0x{:X})",
				thread_handle_out.address(), start_routine, start_context);

			auto t = sys_proc->create_thread(cpu, start_routine);
			cpu.emu()->call_conv()->set_arg(cpu, *t, 0, start_context);

			auto host_obj = std::make_shared<thread_object>(t);
			const auto body_addr = objs.create_object(0, nullptr, 0, host_obj);

			const auto handle = sys_proc->handle_table().create_handle(body_addr, THREAD_ALL_ACCESS);

			if (thread_handle_out)
				thread_handle_out.write(handle);

			if (client_id_out)
			{
				CLIENT_ID cid{};
				cid.UniqueProcess = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(sys_proc->id()));
				cid.UniqueThread = reinterpret_cast<PVOID>(static_cast<std::uintptr_t>(t->id()));
				client_id_out.write(cid);
			}

			LOG_INFO("PsCreateSystemThread: created tid={}, handle=0x{:X}", t->id(), handle);
			return STATUS_SUCCESS;
		});
}
