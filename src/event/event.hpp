#pragma once
#include "event_generated.h"
#include "../emulator/emulator.hpp"
#include "../kernel/thread.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <vector>

using buffer_t = fbs::BufferT;
using argument_ref_t = fbs::ArgumentRefT;
using patch_ref_t = fbs::PatchRefT;
using call_target_t = fbs::CallTargetT;
using ioctl_target_t = fbs::IoctlTargetT;
using event_t = fbs::EventT;
using modified_buffer_t = fbs::ModifiedBufferT;
using event_result_t = fbs::EventResultT;

event_t load_event(const std::filesystem::path& path);
void save_results(const std::filesystem::path& path, const std::vector<event_result_t>& results);

class event_runner_t
{
public:
	explicit event_runner_t(std::shared_ptr<emulator_t> emulator);

	void load_folder(const std::filesystem::path& folder);
	void on_thread_done(const std::shared_ptr<thread_t>& finished);

	[[nodiscard]] const std::vector<event_result_t>& results() const;

private:
	void dispatch_next();
	void collect_result(const std::shared_ptr<thread_t>& finished);

	std::shared_ptr<emulator_t> emulator_;

	std::vector<event_t> queued_events_;
	std::size_t next_event_index_ = 0;

	thread_t::id_type current_event_tid_ = 0;
	emulator_t::address_type current_irp_address_ = 0;
	std::vector<emulator_t::address_type> current_buffer_addresses_;
	const event_t* current_event_ = nullptr;

	std::vector<event_result_t> results_;
};
