#include "win_obj_manager.hpp"

win_obj_manager::win_obj_manager(addr_space& space)
	:	space_(space) {}

addr_t win_obj_manager::create_object(const std::uint8_t type_index,
	const void* body_data, const std::size_t body_size,
	std::shared_ptr<win_object> host, const mem_prot prot)
{
	constexpr auto hdr_size = sizeof(_OBJECT_HEADER);
	const auto base = space_.alloc(hdr_size + body_size, prot);
	const auto body_addr = base + hdr_size;

	_OBJECT_HEADER hdr{};
	hdr.PointerCount = 1;
	hdr.TypeIndex = type_index;

	emu_object<_OBJECT_HEADER> hdr_obj(space_, base);
	hdr_obj.write(hdr);

	if (body_data && body_size > 0)
		space_.write_mem(body_addr, body_data, body_size);

	std::scoped_lock lock(mtx_);
	objects_[body_addr] = { hdr_obj, std::move(host) };
	return body_addr;
}

void win_obj_manager::register_object(addr_t body_addr, std::shared_ptr<win_object> host)
{
	std::scoped_lock lock(mtx_);
	objects_[body_addr] = { emu_object<_OBJECT_HEADER>{}, std::move(host) };
}

bool win_obj_manager::has_object(addr_t body_addr) const
{
	std::scoped_lock lock(mtx_);
	return objects_.contains(body_addr);
}

void win_obj_manager::reference_object(addr_t body_addr)
{
	std::scoped_lock lock(mtx_);
	auto it = objects_.find(body_addr);
	if (it == objects_.end() || !it->second.header) return;
	auto hdr = it->second.header.read();
	++hdr.PointerCount;
	it->second.header.write(hdr);
}

void win_obj_manager::dereference_object(addr_t body_addr)
{
	std::scoped_lock lock(mtx_);
	auto it = objects_.find(body_addr);
	if (it == objects_.end() || !it->second.header) return;
	auto hdr = it->second.header.read();
	--hdr.PointerCount;
	it->second.header.write(hdr);
}

void win_obj_manager::increment_handle_count(addr_t body_addr)
{
	std::scoped_lock lock(mtx_);
	auto it = objects_.find(body_addr);
	if (it == objects_.end() || !it->second.header) return;
	auto hdr = it->second.header.read();
	++hdr.HandleCount;
	it->second.header.write(hdr);
}

void win_obj_manager::decrement_handle_count(addr_t body_addr)
{
	std::scoped_lock lock(mtx_);
	auto it = objects_.find(body_addr);
	if (it == objects_.end() || !it->second.header) return;
	auto hdr = it->second.header.read();
	--hdr.HandleCount;
	it->second.header.write(hdr);
}

win_obj_manager::id_type win_obj_manager::allocate_id()
{
	const auto id = next_id_;
	next_id_ += 4;
	return id;
}
