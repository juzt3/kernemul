#pragma once

#include "../emulator/emulator.hpp"
#include "../emulator/object.hpp"
#include "kernel_def.hpp"

#include <cstdint>
#include <memory>
#include <string>

class handle_table_t;

class process_t
{
public:
	using address_type = emulator_t::address_type;
	using id_type = std::uint64_t;

	explicit process_t(const id_type id, const address_type section_base_address,
		emulator_object_t<_EPROCESS> object, std::string image_name = {})
			:	id_(id),
				section_base_address_(section_base_address),
				object_(std::move(object)),
				image_name_(std::move(image_name)) { }

	[[nodiscard]] id_type id() const
	{
		return id_;
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

	[[nodiscard]] const std::string& name() const
	{
		return image_name_;
	}

	void set_handle_table(std::shared_ptr<handle_table_t> table)
	{
		handle_table_ = std::move(table);
	}

	[[nodiscard]] const std::shared_ptr<handle_table_t>& handle_table() const
	{
		return handle_table_;
	}

	void set_peb_address(const address_type addr)
	{
		peb_address_ = addr;
	}

	[[nodiscard]] address_type peb_address() const
	{
		return peb_address_;
	}

	void set_ki_user_exception_dispatcher(const address_type addr)
	{
		ki_user_exception_dispatcher_ = addr;
	}

	[[nodiscard]] address_type ki_user_exception_dispatcher() const
	{
		return ki_user_exception_dispatcher_;
	}

protected:
	id_type id_;
	address_type section_base_address_;
	emulator_object_t<_EPROCESS> object_;
	std::string image_name_;
	std::shared_ptr<handle_table_t> handle_table_;
	address_type peb_address_ = 0;
	address_type ki_user_exception_dispatcher_ = 0;
};

namespace kernel
{
	void set_up_initial_system_process(const std::shared_ptr<emulator_t>& emulator);

	std::shared_ptr<process_t> create_process(const std::shared_ptr<emulator_t>& emulator,
		process_t::id_type process_id, std::string_view image_name = {},
		emulator_t::address_type section_base_address = 0);
}
