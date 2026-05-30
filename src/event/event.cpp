#include "event.hpp"
#include "../kernel/kernel.hpp"
#include "../kernel/thread.hpp"
#include "../util/file.hpp"
#include "../util/logs.hpp"

#include <flatbuffers/flatbuffers.h>

#include <algorithm>
#include <charconv>
#include <fstream>
#include <regex>
#include <stdexcept>

event_t load_event(const std::filesystem::path& path)
{
	const auto data = util::read_file(path);

	if (!data)
	{
		throw std::runtime_error(std::format("failed to open event file: {}", path.string()));
	}

	flatbuffers::Verifier verifier(data->data(), data->size());

	if (!fbs::VerifyEventBuffer(verifier))
	{
		throw std::runtime_error(std::format("invalid event file: {}", path.string()));
	}

	const auto* event = fbs::GetEvent(data->data());
	event_t result;
	event->UnPackTo(&result);

	return result;
}

void save_results(const std::filesystem::path& path, const std::vector<event_result_t>& results)
{
	flatbuffers::FlatBufferBuilder builder;

	std::vector<flatbuffers::Offset<fbs::EventResult>> result_offsets;

	for (const auto& r : results)
	{
		result_offsets.push_back(fbs::EventResult::Pack(builder, &r));
	}

	auto seq = fbs::CreateResultSequenceDirect(builder, &result_offsets);
	builder.Finish(seq);

	std::ofstream file(path, std::ios::binary);
	file.write(reinterpret_cast<const char*>(builder.GetBufferPointer()), builder.GetSize());
}

static emulator_t::address_type resolve_target_address(const std::string& function)
{
	if (function.starts_with("0x") || function.starts_with("0X"))
	{
		emulator_t::address_type address = 0;
		const auto result = std::from_chars(function.data() + 2, function.data() + function.size(), address, 16);

		if (result.ec != std::errc{})
		{
			throw std::runtime_error(std::format("invalid hex address: {}", function));
		}

		return address;
	}

	for (const auto& module : kernel::module_entries)
	{
		if (const auto symbol = module->find_symbol(function))
		{
			return *symbol;
		}
	}

	throw std::runtime_error(std::format("symbol not found: {}", function));
}

static std::vector<emulator_t::address_type> allocate_buffers(
	const std::shared_ptr<emulator_t>& emulator, const event_t& event)
{
	std::vector<emulator_t::address_type> addresses;
	addresses.reserve(event.buffers.size());

	for (std::size_t i = 0; i < event.buffers.size(); ++i)
	{
		const auto& buf = event.buffers[i];

		if (!buf)
		{
			throw std::runtime_error("null buffer in event");
		}

		const bool has_data = !buf->data.empty();
		const std::uint32_t alloc_size = has_data
			? static_cast<std::uint32_t>(buf->data.size())
			: buf->size;

		if (has_data && buf->size != 0)
		{
			throw std::runtime_error("buffer has both data and size set");
		}

		if (!has_data && buf->size == 0)
		{
			throw std::runtime_error("buffer has neither data nor size set");
		}

		const auto allocation = emulator->heap_allocate(alloc_size, prot_read_write, true);
		emulator_err_t error = allocation.error_or({});
		error.throw_if("event: allocate buffer");

		if (has_data)
		{
			error = emulator->write_virtual_memory(*allocation, buf->data.data(), buf->data.size());
			error.throw_if("event: write buffer data");
		}

		addresses.push_back(*allocation);

		GLOBAL_LOG("event: allocated buffer {} at 0x{:X} (size={})", i, *allocation, alloc_size);
	}

	return addresses;
}

static void apply_buffer_refs(const std::shared_ptr<emulator_t>& emulator,
	const event_t& event, const std::vector<emulator_t::address_type>& addresses,
	std::vector<std::uint64_t>& arguments)
{
	for (const auto& ref : event.buffer_refs)
	{
		if (const auto* arg_ref = ref.AsArgumentRef())
		{
			if (arg_ref->source_buffer >= addresses.size())
			{
				throw std::runtime_error("argument ref source_buffer out of range");
			}

			const auto address = addresses[arg_ref->source_buffer] + arg_ref->source_offset;

			if (arg_ref->arg_index >= arguments.size())
			{
				arguments.resize(arg_ref->arg_index + 1, 0);
			}

			arguments[arg_ref->arg_index] = address;

			GLOBAL_LOG("event: argument {} = buffer {} + 0x{:X} -> 0x{:X}",
				arg_ref->arg_index, arg_ref->source_buffer, arg_ref->source_offset, address);
		}
		else if (const auto* patch = ref.AsPatchRef())
		{
			if (patch->source_buffer >= addresses.size())
			{
				throw std::runtime_error("patch ref source_buffer out of range");
			}

			if (patch->target_buffer >= addresses.size())
			{
				throw std::runtime_error("patch ref target_buffer out of range");
			}

			const auto source_address = addresses[patch->source_buffer] + patch->source_offset;
			const auto target_address = addresses[patch->target_buffer] + patch->target_offset;

			const emulator_err_t error = emulator->write_virtual_memory(
				target_address, &source_address, sizeof(source_address));
			error.throw_if("event: write patch ref");

			GLOBAL_LOG("event: patch buffer {}+0x{:X} -> buffer {}+0x{:X} (0x{:X})",
				patch->source_buffer, patch->source_offset,
				patch->target_buffer, patch->target_offset, source_address);
		}
	}
}

static emulator_t::address_type resolve_event_target(const event_t& event)
{
	if (const auto* call = event.target.AsCallTarget())
	{
		const auto address = resolve_target_address(call->function);
		GLOBAL_LOG("event: call target '{}' resolved to 0x{:X}", call->function, address);
		return address;
	}

	if (event.target.AsIoctlTarget())
	{
		throw std::runtime_error("IOCTL dispatch not yet implemented");
	}

	throw std::runtime_error("event has no target set");
}

event_runner_t::event_runner_t(std::shared_ptr<emulator_t> emulator)
	: emulator_(std::move(emulator))
{
}

void event_runner_t::load_folder(const std::filesystem::path& folder)
{
	if (!std::filesystem::exists(folder))
	{
		GLOBAL_LOG("event: folder '{}' does not exist, skipping", folder.string());
		return;
	}

	std::vector<std::pair<std::uint32_t, std::filesystem::path>> event_files;

	const std::regex pattern(R"(^(\d+)\.event$)");

	for (const auto& entry : std::filesystem::directory_iterator(folder))
	{
		if (!entry.is_regular_file())
		{
			continue;
		}

		std::smatch match;
		const auto filename = entry.path().filename().string();

		if (std::regex_match(filename, match, pattern))
		{
			const auto index = static_cast<std::uint32_t>(std::stoul(match[1].str()));
			event_files.emplace_back(index, entry.path());
		}
	}

	std::sort(event_files.begin(), event_files.end(),
		[](const auto& a, const auto& b) { return a.first < b.first; });

	for (const auto& [index, path] : event_files)
	{
		queued_events_.push_back(load_event(path));
		GLOBAL_LOG("event: loaded {}", path.filename().string());
	}

	GLOBAL_LOG("event: loaded {} events from '{}'", queued_events_.size(), folder.string());
}

void event_runner_t::on_thread_done(const std::shared_ptr<thread_t>& finished)
{
	if (finished == kernel::main_thread)
	{
		GLOBAL_LOG("event: DriverEntry thread finished, dispatching queued events");
		dispatch_next();
		return;
	}

	if (finished->id() == current_event_tid_)
	{
		collect_result(finished);
		dispatch_next();
	}
}

void event_runner_t::dispatch_next()
{
	if (next_event_index_ >= queued_events_.size())
	{
		return;
	}

	const auto& event = queued_events_[next_event_index_];
	current_event_ = &event;

	GLOBAL_LOG("event: dispatching event {} - '{}'", next_event_index_, event.description);

	current_buffer_addresses_ = allocate_buffers(emulator_, event);

	auto arguments = event.arguments;
	apply_buffer_refs(emulator_, event, current_buffer_addresses_, arguments);

	const auto target_address = resolve_event_target(event);

	auto thread = kernel::create_thread_at(emulator_, target_address, arguments);
	current_event_tid_ = thread->id();

	kernel::pending_threads.push(thread);

	++next_event_index_;
}

void event_runner_t::collect_result(const std::shared_ptr<thread_t>& finished)
{
	if (!current_event_)
	{
		return;
	}

	const auto return_value = finished->state().rax;

	GLOBAL_LOG("event: '{}' completed (return_value=0x{:X})", current_event_->description, return_value);

	event_result_t result;
	result.return_value = return_value;
	result.succeeded = true;

	for (std::uint32_t i = 0; i < current_buffer_addresses_.size(); ++i)
	{
		const auto& buf = current_event_->buffers[i];
		const std::uint32_t buf_size = !buf->data.empty()
			? static_cast<std::uint32_t>(buf->data.size())
			: buf->size;

		std::vector<std::uint8_t> read_back(buf_size);
		const emulator_err_t error = emulator_->read_virtual_memory(
			current_buffer_addresses_[i], read_back.data(), buf_size);
		error.throw_if("event: read buffer back");

		auto modified = std::make_unique<modified_buffer_t>();
		modified->index = i;
		modified->data = std::move(read_back);
		result.modified_buffers.push_back(std::move(modified));
	}

	results_.push_back(std::move(result));

	current_event_ = nullptr;
	current_event_tid_ = 0;
	current_buffer_addresses_.clear();
}

const std::vector<event_result_t>& event_runner_t::results() const
{
	return results_;
}
