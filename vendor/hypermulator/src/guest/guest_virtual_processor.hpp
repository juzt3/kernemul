#pragma once
#include "guest_register.hpp"
#include "guest_memory.hpp"

#include <stdexcept>
#include <optional>
#include <atomic>
#include <cstring>
#include <memory>
#include <array>
#include <span>

namespace hm
{
	struct vmexit_context;
	class partition;
	struct reg_t;

	class vcpu
	{
	public:
		vcpu() = default;

		vcpu(std::shared_ptr<partition> partition, const std::uint32_t id)
				:	partition_(std::move(partition)),
					id_(id) { }

		[[nodiscard]] std::uint32_t id() const;

		void run();
		void stop();

		// Stop the processor only if it is at its outermost run. A nested run
		// ends at a trampoline its caller installed, and taking it away hands
		// that caller a result that was never produced.
		void try_stop();

		// 0 is not running, 1 is the outermost run, more than that is a hook
		// that started a run of its own.
		[[nodiscard]] std::uint32_t depth() const;

		[[nodiscard]] std::optional<addr_t> virt_to_phys(addr_t virt_addr) const;

		bool write_virt_mem(addr_t virt_addr, const void* buf, std::size_t size);
		bool write_virt_mem(addr_t virt_addr, std::span<const std::uint8_t> buf);

		bool read_virt_mem(addr_t virt_addr, void* buf, std::size_t size) const;
		bool read_virt_mem(addr_t virt_addr, std::span<std::uint8_t> buf) const;

		bool read_mem(addr_t addr, void* buf, std::size_t size) const;
		bool read_mem(addr_t addr, std::span<std::uint8_t> buf) const;

		bool write_mem(addr_t addr, const void* buf, std::size_t size);
		bool write_mem(addr_t addr, std::span<const std::uint8_t> buf);

		bool reg_write(const reg_t& r, const void* value, std::size_t size);
		bool reg_read(const reg_t& r, void* value, std::size_t size) const;

		[[nodiscard]] bool uses_paging() const;

		template <reg_t Register, class T>
		[[nodiscard]] T reg_read() const
		{
			static_assert(std::is_trivially_copyable_v<T>, "reading non trivially copyable type from a register");
		
			T value = { };
			bool status;

			if constexpr (sizeof(T) == Register.size)
			{
				status = reg_read(Register, &value, sizeof(T));
			}
			else
			{
				std::array<std::uint8_t, Register.size> buf = { };

				status = reg_read(Register, buf.data(), buf.size());

				const std::size_t copy_size = std::min(sizeof(T), static_cast<std::size_t>(Register.size));

				std::memcpy(&value, buf.data(), copy_size);
			}

			if (!status)
			{
				throw std::runtime_error("unable to read register value");
			}

			return value;
		}

		template <reg_t Register, class T>
		void reg_write(const T& value)
		{
			static_assert(std::is_trivially_copyable_v<T>, "writing non trivially copyable type to a register");
			static_assert(sizeof(T) <= Register.size, "writing too large of a value to a register");

			bool status;

			if constexpr (sizeof(T) == Register.size)
			{
				status = reg_write(Register, &value, sizeof(T));
			}
			else
			{
				std::array<std::uint8_t, Register.size> buf = { };

				std::memcpy(buf.data(), &value, sizeof(T));

				status = reg_write(Register, buf.data(), buf.size());
			}

			if (!status)
			{
				throw std::runtime_error("unable to write register value");
			}
		}

	protected:
		[[nodiscard]] bool process_vmexit(vmexit_context& context);

		// True if the pending stop was aimed at the run at this depth, which
		// also consumes it: an outer run carries on once the run the stop was
		// meant for has returned.
		[[nodiscard]] bool take_stop(std::uint32_t depth) const;

		void reset_exception_state();

		std::shared_ptr<partition> partition_ = { };
		std::uint32_t id_ = 0;

		// Shared by every copy of the processor, since a processor is handed
		// out by value and a stop has to reach the run it was aimed at.
		std::shared_ptr<std::atomic<std::uint32_t>> depth_ = std::make_shared<std::atomic<std::uint32_t>>(0);
		std::shared_ptr<std::atomic<std::uint32_t>> stop_depth_ = std::make_shared<std::atomic<std::uint32_t>>(0);
	};
}
