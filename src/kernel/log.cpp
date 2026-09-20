#include "../util/log.hpp"
#include "thread_scheduler.hpp"

namespace
{
	thread_local vcpu* log_cpu = nullptr;
}

void set_log_cpu(vcpu* const cpu)
{
	log_cpu = cpu;
}

std::uint32_t log_cpu_id()
{
	return log_cpu ? static_cast<std::uint32_t>(log_cpu->id()) : 0;
}

std::uint32_t log_thread_id()
{
	const auto t = log_cpu ? log_cpu->thread() : nullptr;
	return t ? t->id() : 0;
}

std::uint32_t log_process_id()
{
	const auto t = log_cpu ? log_cpu->thread() : nullptr;
	return t && t->proc() ? t->proc()->id() : 0;
}

std::string_view log_mode()
{
	const auto t = log_cpu ? log_cpu->thread() : nullptr;
	return t && t->is_user_mode() ? "user" : "kernel";
}
