#include "handle_table.hpp"
#include "object_manager.hpp"

handle_table_t::handle_table_t(std::shared_ptr<emulator_t> emulator,
	std::shared_ptr<object_manager_t> object_manager)
	: emulator_(std::move(emulator)),
	  object_manager_(std::move(object_manager))
{
}

handle_table_t::handle_type handle_table_t::create_handle(
	const emulator_t::address_type body_address, const access_type access)
{
	if (!object_manager_->has_registered_object(body_address))
	{
		throw std::runtime_error("handle_table: create_handle for unknown object");
	}

	const handle_type handle = allocate_handle();

	handles_[handle] = { body_address, access };

	const emulator_t::address_type header_address = body_address - sizeof(_OBJECT_HEADER);

	std::int64_t handle_count = 0;
	emulator_err_t error = emulator_->read_virtual_memory(
		header_address + offsetof(_OBJECT_HEADER, HandleCount), &handle_count, sizeof(handle_count));
	error.throw_if("handle_table: read HandleCount");

	++handle_count;

	error = emulator_->write_virtual_memory(
		header_address + offsetof(_OBJECT_HEADER, HandleCount), &handle_count, sizeof(handle_count));
	error.throw_if("handle_table: write HandleCount");

	return handle;
}

bool handle_table_t::close_handle(const handle_type handle)
{
	const auto it = handles_.find(handle);

	if (it == handles_.end())
	{
		return false;
	}

	const emulator_t::address_type body_address = it->second.body_address;

	handles_.erase(it);

	const auto total_size = object_manager_->object_total_size(body_address);

	if (total_size > 0)
	{
		const emulator_t::address_type header_address = body_address - sizeof(_OBJECT_HEADER);

		std::int64_t handle_count = 0;
		const emulator_err_t error = emulator_->read_virtual_memory(
			header_address + offsetof(_OBJECT_HEADER, HandleCount), &handle_count, sizeof(handle_count));
		error.throw_if("handle_table: read HandleCount");

		--handle_count;

		const emulator_err_t write_error = emulator_->write_virtual_memory(
			header_address + offsetof(_OBJECT_HEADER, HandleCount), &handle_count, sizeof(handle_count));
		write_error.throw_if("handle_table: write HandleCount");
	}

	return true;
}

std::optional<handle_table_t::handle_entry_t> handle_table_t::lookup_handle(const handle_type handle) const
{
	const auto it = handles_.find(handle);

	if (it == handles_.end())
	{
		return std::nullopt;
	}

	return it->second;
}

handle_table_t::handle_type handle_table_t::allocate_handle()
{
	const handle_type handle = next_handle_;
	next_handle_ += 4;
	return handle;
}
