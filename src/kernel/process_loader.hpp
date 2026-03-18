#pragma once

#include "../emulator/emulator.hpp"
#include "../emulator/object.hpp"
#include "kernel_def.hpp"

#include <cstdint>
#include <memory>
#include <string>

class process_t
{
public:
	using address_type = emulator_t::address_type;
	using id_type = std::uint64_t;

	explicit process_t(const id_type process_id, const address_type section_base_address, emulator_object_t<_EPROCESS> object)
			:	process_id_(process_id),
				section_base_address_(section_base_address),
				object_(std::move(object)) { }

	[[nodiscard]] id_type process_id() const
	{
		return process_id_;
	}

	[[nodiscard]] address_type section_base_address() const
	{
		return section_base_address_;
	}

	[[nodiscard]] address_type address() const
	{
		return object_.address();
	}

	[[nodiscard]] emulator_object_t<_EPROCESS>& object()
	{
		return object_;
	}

	[[nodiscard]] const emulator_object_t<_EPROCESS>& object() const
	{
		return object_;
	}

protected:
	id_type process_id_;
	address_type section_base_address_;
	emulator_object_t<_EPROCESS> object_;
};

namespace kernel
{
	void set_up_initial_system_process(const std::shared_ptr<emulator_t>& emulator);

	std::shared_ptr<process_t> create_process(const std::shared_ptr<emulator_t>& emulator,
		process_t::id_type process_id, emulator_t::address_type section_base_address = 0);
}
