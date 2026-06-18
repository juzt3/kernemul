#include "object_manager.hpp"
#include "../util/logs.hpp"

#include <Windows.h>

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

bool object_manager_t::has_registered_object(const emulator_t::address_type body_address) const
{
	return objects_.contains(body_address);
}

std::size_t object_manager_t::object_total_size(const emulator_t::address_type body_address) const
{
	const auto it = objects_.find(body_address);

	if (it == objects_.end())
	{
		return 0;
	}

	return it->second.total_size;
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

std::uint64_t object_manager_t::allocate_id()
{
	const auto id = next_id_;
	next_id_ += 4;
	return id;
}

void object_manager_t::register_named_object(const std::string& path, const emulator_t::address_type body_address)
{
	std::string normalized = path;

	for (auto& c : normalized)
	{
		if (c == '/')
		{
			c = '\\';
		}

		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}

	named_objects_[normalized] = body_address;
}

std::optional<emulator_t::address_type> object_manager_t::lookup_named_object(const std::string& path) const
{
	std::string normalized = path;

	for (auto& c : normalized)
	{
		if (c == '/')
		{
			c = '\\';
		}

		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}

	const auto it = named_objects_.find(normalized);

	if (it == named_objects_.end())
	{
		return std::nullopt;
	}

	return it->second;
}
