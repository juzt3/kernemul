#include "object_manager.hpp"
#include "../util/logs.hpp"

#include <Windows.h>

registry_key_object_t::~registry_key_object_t()
{
	if (host_key)
	{
		RegCloseKey(static_cast<HKEY>(host_key));
		host_key = nullptr;
	}
}

object_manager_t::object_manager_t(std::shared_ptr<emulator_t> emulator)
	: emulator_(std::move(emulator))
{
}

emulator_t::address_type object_manager_t::create_object(
	const emulator_t::address_type type_address,
	const void* body_data,
	const std::size_t body_size,
	std::shared_ptr<object_t> object)
{
	constexpr std::size_t header_size = sizeof(_OBJECT_HEADER);
	const std::size_t total_size = header_size + body_size;

	const auto allocation = emulator_->heap_allocate(total_size, prot_read_write, true);
	emulator_err_t error = allocation.error_or({});
	error.throw_if("object_manager: allocate object");

	const emulator_t::address_type header_address = *allocation;
	const emulator_t::address_type body_address = header_address + header_size;

	_OBJECT_HEADER header{};
	header.PointerCount = 1;
	header.HandleCount = 0;
	header.TypeIndex = static_cast<UCHAR>(type_address & 0xFF);

	error = emulator_->write_virtual_memory(header_address, &header, sizeof(header));
	error.throw_if("object_manager: write object header");

	if (body_data && body_size > 0)
	{
		error = emulator_->write_virtual_memory(body_address, body_data, body_size);
		error.throw_if("object_manager: write object body");
	}

	objects_[body_address] = { total_size, std::move(object) };

	return body_address;
}

void object_manager_t::register_object(
	const emulator_t::address_type body_address,
	std::shared_ptr<object_t> object)
{
	objects_[body_address] = { 0, std::move(object) };
}

object_manager_t::handle_type object_manager_t::create_handle(
	const emulator_t::address_type body_address, const access_type access)
{
	const auto it = objects_.find(body_address);

	if (it == objects_.end())
	{
		throw std::runtime_error("object_manager: create_handle for unknown object");
	}

	const handle_type handle = allocate_handle();

	handles_[handle] = { body_address, access };

	const emulator_t::address_type header_address = body_address - sizeof(_OBJECT_HEADER);

	LONGLONG handle_count = 0;
	emulator_err_t error = emulator_->read_virtual_memory(
		header_address + offsetof(_OBJECT_HEADER, HandleCount), &handle_count, sizeof(handle_count));
	error.throw_if("object_manager: read HandleCount");

	++handle_count;

	error = emulator_->write_virtual_memory(
		header_address + offsetof(_OBJECT_HEADER, HandleCount), &handle_count, sizeof(handle_count));
	error.throw_if("object_manager: write HandleCount");

	return handle;
}

bool object_manager_t::close_handle(const handle_type handle)
{
	const auto it = handles_.find(handle);

	if (it == handles_.end())
	{
		return false;
	}

	const emulator_t::address_type body_address = it->second.body_address;

	handles_.erase(it);

	const auto obj_it = objects_.find(body_address);

	if (obj_it != objects_.end() && obj_it->second.total_size > 0)
	{
		const emulator_t::address_type header_address = body_address - sizeof(_OBJECT_HEADER);

		LONGLONG handle_count = 0;
		const emulator_err_t error = emulator_->read_virtual_memory(
			header_address + offsetof(_OBJECT_HEADER, HandleCount), &handle_count, sizeof(handle_count));
		error.throw_if("object_manager: read HandleCount");

		--handle_count;

		const emulator_err_t write_error = emulator_->write_virtual_memory(
			header_address + offsetof(_OBJECT_HEADER, HandleCount), &handle_count, sizeof(handle_count));
		write_error.throw_if("object_manager: write HandleCount");
	}

	return true;
}

std::optional<object_manager_t::handle_entry_t> object_manager_t::lookup_handle(const handle_type handle) const
{
	const auto it = handles_.find(handle);

	if (it == handles_.end())
	{
		return std::nullopt;
	}

	return it->second;
}

void object_manager_t::reference_object(const emulator_t::address_type body_address)
{
	const auto it = objects_.find(body_address);

	if (it == objects_.end() || it->second.total_size == 0)
	{
		return;
	}

	const emulator_t::address_type header_address = body_address - sizeof(_OBJECT_HEADER);

	LONGLONG pointer_count = 0;
	emulator_err_t error = emulator_->read_virtual_memory(
		header_address + offsetof(_OBJECT_HEADER, PointerCount), &pointer_count, sizeof(pointer_count));
	error.throw_if("object_manager: read PointerCount");

	++pointer_count;

	error = emulator_->write_virtual_memory(
		header_address + offsetof(_OBJECT_HEADER, PointerCount), &pointer_count, sizeof(pointer_count));
	error.throw_if("object_manager: write PointerCount");
}

void object_manager_t::dereference_object(const emulator_t::address_type body_address)
{
	const auto it = objects_.find(body_address);

	if (it == objects_.end() || it->second.total_size == 0)
	{
		return;
	}

	const emulator_t::address_type header_address = body_address - sizeof(_OBJECT_HEADER);

	LONGLONG pointer_count = 0;
	emulator_err_t error = emulator_->read_virtual_memory(
		header_address + offsetof(_OBJECT_HEADER, PointerCount), &pointer_count, sizeof(pointer_count));
	error.throw_if("object_manager: read PointerCount");

	--pointer_count;

	error = emulator_->write_virtual_memory(
		header_address + offsetof(_OBJECT_HEADER, PointerCount), &pointer_count, sizeof(pointer_count));
	error.throw_if("object_manager: write PointerCount");
}

object_manager_t::handle_type object_manager_t::allocate_handle()
{
	const handle_type handle = next_handle_;
	next_handle_ += 4;
	return handle;
}

std::uint64_t object_manager_t::allocate_id()
{
	const auto id = next_id_;
	next_id_ += 4;
	return id;
}
