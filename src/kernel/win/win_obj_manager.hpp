#pragma once
#include "types.hpp"
#include "../../emu/object.hpp"
#include "../../util/string.hpp"

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

struct win_object
{
	virtual ~win_object() = default;
};

struct thread_object final : win_object
{
	std::shared_ptr<class thread> thread;
	explicit thread_object(std::shared_ptr<class thread> t) : thread(std::move(t)) {}
};

struct object_entry
{
	emu_object<_OBJECT_HEADER> header;
	std::shared_ptr<win_object> host;
};

class win_obj_manager
{
public:
	explicit win_obj_manager(addr_space& space);

	// prot is the object's memory: everything the guest reaches only from
	// kernel mode belongs behind prot_supervisor.
	addr_t create_object(std::uint8_t type_index,
		const void* body_data, std::size_t body_size,
		std::shared_ptr<win_object> host = {}, mem_prot prot = prot_rw);

	void register_object(addr_t body_addr, std::shared_ptr<win_object> host);

	// The object namespace, holding exactly what the guest put in it: nothing
	// here builds \Device or \BaseNamedObjects up front.
	void register_named_object(std::string name, addr_t body_addr);

	[[nodiscard]] addr_t lookup_named_object(std::string_view name) const;

	template <typename T>
	[[nodiscard]] std::shared_ptr<T> get_object(addr_t body_addr) const
	{
		std::scoped_lock lock(mtx_);
		const auto it = objects_.find(body_addr);
		if (it == objects_.end() || !it->second.host)
			return {};
		return std::dynamic_pointer_cast<T>(it->second.host);
	}

	[[nodiscard]] bool has_object(addr_t body_addr) const;

	// The header sits directly in front of the body, which is all a caller
	// holding an object pointer needs to know to reach it.
	[[nodiscard]] emu_object<_OBJECT_HEADER> header_of(addr_t body_addr) const
	{
		return emu_object<_OBJECT_HEADER>(space_, body_addr - sizeof(_OBJECT_HEADER));
	}

	void reference_object(addr_t body_addr);
	void dereference_object(addr_t body_addr);
	void increment_handle_count(addr_t body_addr);
	void decrement_handle_count(addr_t body_addr);

	using id_type = std::uint32_t;

	id_type allocate_id();

private:
	addr_space& space_;
	mutable std::mutex mtx_;
	std::unordered_map<addr_t, object_entry> objects_;
	std::unordered_map<std::string, addr_t, string_view_hash, std::equal_to<>> named_;
	id_type next_id_ = 4;
};
