#pragma once
#include "emulator.hpp"

#include "../util/logs.hpp"

template <class T>
class emulator_object_t
{
public:
	using address_type = emulator_t::address_type;
	using size_type = emulator_t::size_type;

	emulator_object_t() = default;

	explicit emulator_object_t(const std::shared_ptr<emulator_t>& emulator, const address_type address,
	                           const std::string& name, const bool monitor)
			:	emulator_(emulator),
				name_(name),
				address_(address)
	{
		if (monitor)
		{
			const emulator_err_t error = emulator_->hook_memory(
				[emulator, address, name](const emulator_t::address_type accessed_address, const protection_t access) -> bool
				{
					const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();
					const size_type offset = accessed_address - address;

					THREAD_LOG("instruction at 0x{:X} accessed ({} '{}')+0x{:X} (type={})", rip, get_type_name(), name, offset, static_cast<std::uint32_t>(access));

					return false;
				},
				prot_read_write,
				address,
				address + sizeof(T)
			).error_or({});

			error.throw_if("object hook attach");
		}
	}

	void write(const T& value)
	{
		const emulator_err_t error = emulator_->write_virtual_memory(address_, &value, sizeof(T));

		error.throw_if("writing object");
	}

	[[nodiscard]] T read() const
	{
		T value = { };

		const emulator_err_t error = emulator_->read_virtual_memory(address_, &value, sizeof(T));

		error.throw_if("reading object");

		return value;
	}

	[[nodiscard]] address_type address() const
	{
		return address_;
	}

	[[nodiscard]] const std::shared_ptr<emulator_t>& get_emulator() const
	{
		return emulator_;
	}

	static emulator_object_t allocate_at(const std::shared_ptr<emulator_t>& emulator, const address_type address, const std::string& name = { }, const bool monitor = false)
	{
		const auto error = emulator->map_virtual_memory(address, sizeof(T), prot_read_write);

		error.throw_if("object allocation");

		return emulator_object_t{ emulator, address, name, monitor };
	}

	static emulator_object_t allocate_at(const std::shared_ptr<emulator_t>& emulator, const T& value, const address_type address, const std::string& name = { }, const bool monitor = false)
	{
		emulator_object_t object = allocate_at(emulator, address, name, monitor);

		object.write(value);

		return std::move(object);
	}

	static emulator_object_t allocate(const std::shared_ptr<emulator_t>& emulator, const std::string& name = { }, const bool monitor = false)
	{
		const auto allocation = emulator->heap_allocate(sizeof(T), prot_read_write, true);

		if (!allocation)
		{
			throw std::runtime_error("unable to allocate object on heap");
		}

		return emulator_object_t{ emulator, *allocation, name, monitor };
	}

	static emulator_object_t allocate(const std::shared_ptr<emulator_t>& emulator, const T& value, const std::string& name = { }, const bool monitor = false)
	{
		emulator_object_t object = allocate(emulator, name, monitor);

		object.write(value);

		return std::move(object);
	}

	static emulator_object_t view_at(const std::shared_ptr<emulator_t>& emulator, const address_type address, const std::string& name = { }, const bool monitor = false)
	{
		return emulator_object_t{ emulator, address, name, monitor };
	}

protected:
	[[nodiscard]] static std::string_view get_type_name()
	{
		return typeid(T).name();
	}

	std::shared_ptr<emulator_t> emulator_ = { };
	std::shared_ptr<emulator_hook_t> hook_ = { };

	std::string name_ = { };
	address_type address_ = 0;
};
