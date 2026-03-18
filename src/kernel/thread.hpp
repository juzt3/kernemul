#pragma once

#include "../emulator/emulator.hpp"
#include "../emulator/object.hpp"
#include "kernel_def.hpp"
#include "process_loader.hpp"

#include <cstdint>
#include <memory>

class thread_t
{
public:
	using address_type = emulator_t::address_type;
	using id_type = std::uint64_t;

	explicit thread_t(const id_type id, std::shared_ptr<process_t> process, emulator_object_t<_ETHREAD> object)
			:	id_(id),
				process_(std::move(process)),
				object_(std::move(object)) { }

	[[nodiscard]] id_type id() const
	{
		return id_;
	}

	[[nodiscard]] const std::shared_ptr<process_t>& process() const
	{
		return process_;
	}

	[[nodiscard]] address_type address() const
	{
		return object_.address();
	}

	[[nodiscard]] emulator_object_t<_ETHREAD>& object()
	{
		return object_;
	}

	[[nodiscard]] const emulator_object_t<_ETHREAD>& object() const
	{
		return object_;
	}

protected:
	id_type id_;
	std::shared_ptr<process_t> process_;
	emulator_object_t<_ETHREAD> object_;
};

namespace kernel
{
	[[nodiscard]] std::shared_ptr<thread_t> create_thread(const std::shared_ptr<emulator_t>& emulator,
		thread_t::id_type thread_id, const std::shared_ptr<process_t>& process);
}
