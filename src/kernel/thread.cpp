#include "thread.hpp"
#include "kernel.hpp"
#include "../emulator/object.hpp"

#include <spdlog/spdlog.h>

#include <format>

std::shared_ptr<thread_t> kernel::create_thread(const std::shared_ptr<emulator_t>& emulator,
	const thread_t::id_type thread_id, const std::shared_ptr<process_t>& process)
{
	const auto name = std::format("ETHREAD_{}", thread_id);

	_ETHREAD contents = { };

	contents.Tcb.ApcState.Process = contents.Tcb.Process = reinterpret_cast<_KPROCESS*>(process->address());
	contents.Cid.UniqueProcess = reinterpret_cast<HANDLE>(process->id());
	contents.Cid.UniqueThread = reinterpret_cast<HANDLE>(thread_id);

	auto object = emulator_object_t<_ETHREAD>::allocate(emulator, contents, name);

	auto thread = std::make_shared<thread_t>(thread_id, process, std::move(object));

	spdlog::info("created thread (tid={}, pid={}, address=0x{:X})",
		thread_id, process->id(), thread->address());

	return thread;
}
