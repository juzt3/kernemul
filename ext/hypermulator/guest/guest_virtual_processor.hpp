#pragma once
#include "guest_register.hpp"

#include <stdexcept>
#include <optional>
#include <memory>
#include <array>
#include <span>

namespace hm
{
	struct vmexit_context_t;
	class guest_partition_t;
	struct guest_register_t;

	class guest_virtual_processor_t
	{
	public:
		using address_type = std::uintptr_t;
		using protection_type = std::uint32_t;
		using size_type = std::size_t;
		using id_type = std::uint32_t;

		guest_virtual_processor_t() = default;

		guest_virtual_processor_t(std::shared_ptr<guest_partition_t> partition, const id_type id)
				:	partition_(std::move(partition)),
					id_(id) { }

		[[nodiscard]] id_type id() const;

		void run();

		[[nodiscard]] std::optional<address_type> translate_virtual_address(address_type virtual_address) const;

		bool write_virtual_memory(address_type virtual_address, const void* buffer, size_type size);
		bool write_virtual_memory(address_type virtual_address, std::span<const std::uint8_t> buffer);

		bool read_virtual_memory(address_type virtual_address, void* buffer, size_type size) const;
		bool read_virtual_memory(address_type virtual_address, std::span<std::uint8_t> buffer) const;

		bool read_memory(address_type address, void* buffer, size_type size) const;
		bool read_memory(address_type address, std::span<std::uint8_t> buffer) const;

		bool write_memory(address_type address, const void* buffer, size_type size);
		bool write_memory(address_type address, std::span<const std::uint8_t> buffer);

		bool write_register(const guest_register_t& guest_register, const void* value, size_type size);
		bool read_register(const guest_register_t& guest_register, void* value, size_type size) const;

		[[nodiscard]] bool uses_paging() const;

		template <guest_register_t Register, class T>
		[[nodiscard]] T read_register() const
		{
			static_assert(std::is_trivially_copyable_v<T>, "reading non trivially copyable type from a register");
		
			T value = { };
			bool status;

			if constexpr (sizeof(T) == Register.size)
			{
				status = read_register(Register, &value, sizeof(T));
			}
			else
			{
				std::array<std::uint8_t, Register.size> buffer = { };

				status = read_register(Register, buffer.data(), buffer.size());

				const size_type copy_size = std::min(sizeof(T), static_cast<std::size_t>(Register.size));

				std::memcpy(&value, buffer.data(), copy_size);
			}

			if (!status)
			{
				throw std::runtime_error("unable to read register value");
			}

			return value;
		}

		template <guest_register_t Register, class T>
		void write_register(const T& value)
		{
			static_assert(std::is_trivially_copyable_v<T>, "writing non trivially copyable type to a register");
			static_assert(sizeof(T) <= Register.size, "writing too large of a value to a register");

			bool status;

			if constexpr (sizeof(T) == Register.size)
			{
				status = write_register(Register, &value, sizeof(T));
			}
			else
			{
				std::array<std::uint8_t, Register.size> buffer = { };

				std::memcpy(buffer.data(), &value, sizeof(T));

				status = write_register(Register, buffer.data(), buffer.size());
			}

			if (!status)
			{
				throw std::runtime_error("unable to write register value");
			}
		}

	protected:
		[[nodiscard]] bool process_vmexit(vmexit_context_t& context);

		void reset_exception_state();

		std::shared_ptr<guest_partition_t> partition_ = { };
		id_type id_ = 0;
	};
}
