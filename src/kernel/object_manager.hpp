#pragma once
#include "../emulator/emulator.hpp"
#include "kernel_def.hpp"

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

class file_t;
class thread_t;
class registry_key_t;

struct object_t
{
	virtual ~object_t() = default;
};

struct file_object_t final : object_t
{
	std::shared_ptr<file_t> file;
	std::string path;
	std::size_t directory_offset = 0;

	file_object_t(std::shared_ptr<file_t> file, std::string path)
			:	file(std::move(file)),
				path(std::move(path)) { }
};

struct thread_object_t final : object_t
{
	std::shared_ptr<thread_t> thread;

	explicit thread_object_t(std::shared_ptr<thread_t> thread)
			:	thread(std::move(thread)) { }
};

struct registry_key_object_t final : object_t
{
	std::shared_ptr<registry_key_t> key;
	std::string path;
};

struct callback_object_t final : object_t
{
};

struct callback_registration_object_t final : object_t
{
};

struct ob_callback_object_t final : object_t
{
};

struct device_object_t final : object_t
{
};

struct directory_object_t final : object_t
{
	std::string name;

	explicit directory_object_t(std::string name)
			:	name(std::move(name)) { }
};

struct section_object_t final : object_t
{
	std::shared_ptr<file_t> file;
	bool is_image = false;
	std::uint64_t preferred_base = 0;

	explicit section_object_t(std::shared_ptr<file_t> file)
			:	file(std::move(file)) { }
};

struct event_object_t final : object_t
{
	enum type_t : std::uint32_t { notification = 0, synchronization = 1 };
	type_t event_type;
	bool signaled;

	event_object_t(const type_t type, const bool initial)
			:	event_type(type), signaled(initial) { }
};

struct mutant_object_t final : object_t
{
	bool owned = false;
	std::uint64_t owner_thread_id = 0;
	std::int32_t count = 0;

	explicit mutant_object_t(const bool initial_owner, const std::uint64_t tid = 0)
			:	owned(initial_owner), owner_thread_id(initial_owner ? tid : 0),
				count(initial_owner ? 1 : 0) { }
};

struct semaphore_object_t final : object_t
{
	std::int32_t count;
	std::int32_t max_count;

	semaphore_object_t(const std::int32_t initial, const std::int32_t max)
			:	count(initial), max_count(max) { }
};

struct keyed_event_object_t final : object_t
{
};

struct alpc_port_object_t final : object_t
{
	std::string port_name;
	bool is_server_port = false;

	struct queued_message_t
	{
		std::vector<std::uint8_t> data;
	};
	std::vector<queued_message_t> message_queue;

	struct pending_receive_t
	{
		thread_t* waiting_thread = nullptr;
		emulator_t::address_type receive_buffer = 0;
		emulator_t::address_type buffer_length_ptr = 0;
		std::uint64_t buffer_length = 0;
	};
	std::optional<pending_receive_t> pending_receive;

	std::shared_ptr<alpc_port_object_t> peer_port;

	explicit alpc_port_object_t(std::string name, const bool server)
		: port_name(std::move(name)), is_server_port(server) { }
};

struct object_entry_t
{
	std::size_t total_size;
	std::shared_ptr<object_t> object;
};

class object_manager_t
{
public:
	using handle_type = std::uint64_t;
	using access_type = std::uint32_t;

	enum access_mask : access_type
	{
		access_none           = 0,
		delete_access         = 0x00010000,
		synchronize           = 0x00100000,
		generic_read          = 0x80000000,
		generic_write         = 0x40000000,
		generic_execute       = 0x20000000,
		generic_all           = 0x10000000,
		file_read_data        = 0x0001,
		file_write_data       = 0x0002,
		file_append_data      = 0x0004,
	};

	struct handle_entry_t
	{
		emulator_t::address_type body_address;
		access_type access;
	};

	explicit object_manager_t(std::shared_ptr<emulator_t> emulator);

	[[nodiscard]] emulator_t::address_type create_object(
		emulator_t::address_type type_address,
		const void* body_data,
		std::size_t body_size,
		std::shared_ptr<object_t> object = {}
	);

	void register_object(
		emulator_t::address_type body_address,
		std::shared_ptr<object_t> object = {}
	);

	template <typename T>
	[[nodiscard]] std::shared_ptr<T> get_object(emulator_t::address_type body_address) const
	{
		const auto it = objects_.find(body_address);

		if (it == objects_.end() || !it->second.object)
		{
			return {};
		}

		return std::dynamic_pointer_cast<T>(it->second.object);
	}

	[[nodiscard]] bool has_registered_object(emulator_t::address_type body_address) const;
	[[nodiscard]] std::size_t object_total_size(emulator_t::address_type body_address) const;

	void reference_object(emulator_t::address_type body_address);
	void dereference_object(emulator_t::address_type body_address);

	void register_named_object(const std::string& path, emulator_t::address_type body_address);
	[[nodiscard]] std::optional<emulator_t::address_type> lookup_named_object(const std::string& path) const;

	[[nodiscard]] std::uint64_t allocate_id();

private:
	std::shared_ptr<emulator_t> emulator_;
	std::unordered_map<emulator_t::address_type, object_entry_t> objects_;
	std::unordered_map<std::string, emulator_t::address_type> named_objects_;
	std::uint64_t next_id_ = 4;
};
