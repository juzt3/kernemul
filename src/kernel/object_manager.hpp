#pragma once
#include "../emulator/emulator.hpp"
#include "kernel_def.hpp"

#include <memory>
#include <optional>
#include <unordered_map>

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

struct section_object_t final : object_t
{
	std::shared_ptr<file_t> file;

	explicit section_object_t(std::shared_ptr<file_t> file)
			:	file(std::move(file)) { }
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

	[[nodiscard]] handle_type create_handle(emulator_t::address_type body_address, access_type access);
	bool close_handle(handle_type handle);
	[[nodiscard]] std::optional<handle_entry_t> lookup_handle(handle_type handle) const;

	template <typename T>
	[[nodiscard]] std::shared_ptr<T> get_object(emulator_t::address_type body_address) const
	{
		const auto it = objects_.find(body_address);

		if (it == objects_.end() || !it->second.object)
		{
			return {};
		}

		return std::static_pointer_cast<T>(it->second.object);
	}

	template <typename T>
	[[nodiscard]] std::shared_ptr<T> get_object_from_handle(handle_type handle) const
	{
		const auto entry = lookup_handle(handle);

		if (!entry)
		{
			return {};
		}

		return get_object<T>(entry->body_address);
	}

	void reference_object(emulator_t::address_type body_address);
	void dereference_object(emulator_t::address_type body_address);

	void register_named_object(const std::string& path, emulator_t::address_type body_address);
	[[nodiscard]] std::optional<emulator_t::address_type> lookup_named_object(const std::string& path) const;

	[[nodiscard]] std::uint64_t allocate_id();

private:
	[[nodiscard]] handle_type allocate_handle();

	std::shared_ptr<emulator_t> emulator_;
	std::unordered_map<emulator_t::address_type, object_entry_t> objects_;
	std::unordered_map<handle_type, handle_entry_t> handles_;
	std::unordered_map<std::string, emulator_t::address_type> named_objects_;
	handle_type next_handle_ = 4;
	std::uint64_t next_id_ = 4;
};
