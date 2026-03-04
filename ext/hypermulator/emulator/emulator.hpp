#pragma once
#include "../guest/guest_partition.hpp"
#include "../guest/guest_register.hpp"
#include "../guest/guest_virtual_processor.hpp"

#include <variant>

namespace hm
{
	enum class hook_instruction_t : std::uint8_t
	{
		rdtsc,
		cpuid
	};

	struct hook_memory_t
	{
		protection_t protection;

		[[nodiscard]] bool exits_on(const memory_vmexit_t::access access) const
		{
			return (access == memory_vmexit_t::access::read && protection & prot_read) ||
				(access == memory_vmexit_t::access::write && protection & prot_write) ||
				(access == memory_vmexit_t::access::execute && protection & prot_execute);
		}
	};

	struct hook_basic_block_t
	{
		bool was_control_flow;
	};

	enum class hook_type_t : std::uint8_t
	{
		code,
		basic_block,
		instruction,
		invalid_memory,
		memory_access
	};

	struct hook_t
	{
		using address_type = guest_partition_t::address_type;
		using instruction_callback = std::function<bool()>; // returns true = skip instruction
		using code_callback = std::function<void()>;
		using memory_access_callback = std::function<void(address_type address, memory_vmexit_t::access access)>;
		using invalid_memory_callback = std::function<bool(address_type address, memory_vmexit_t::access access)>; // returns true = has handled invalid access properly (e.g. mapping address in)

		using callback_type = std::variant<instruction_callback, code_callback, memory_access_callback, invalid_memory_callback>;
		using data_type = std::variant<hook_instruction_t, hook_memory_t, hook_basic_block_t>;

		callback_type callback;
		hook_type_t type;

		address_type start_address;
		address_type end_address;

		data_type extra_data;

		[[nodiscard]] bool in_range(address_type address) const;
		[[nodiscard]] bool in_aligned_range(address_type address) const;
	};

	class emulator_t
	{
	public:
		using address_type = std::uintptr_t;
		using size_type = std::size_t;
		using protection_type = std::uint32_t;

		using code_page_intercept_type = std::function<void(std::span<const std::uint8_t>)>;

		constexpr static address_type reserved_base = 0x1000;
		constexpr static address_type default_start_address = 0;
		constexpr static address_type default_end_address = std::numeric_limits<address_type>::max();
		constexpr static size_type page_size = guest_partition_t::page_size;

		explicit emulator_t(machine_mode_t mode);

		[[nodiscard]] bool run_at(address_type start_address, address_type end_address = 0);

		std::shared_ptr<hook_t> hook_code(const hook_t::code_callback& callback, address_type start_physical_address = default_start_address, address_type end_physical_address = default_end_address);
		std::shared_ptr<hook_t> hook_basic_block(const hook_t::code_callback& callback, address_type start_physical_address = default_start_address, address_type end_physical_address = default_end_address);
		std::shared_ptr<hook_t> hook_memory(protection_type protection, const hook_t::memory_access_callback& callback, address_type start_physical_address = default_start_address, address_type end_physical_address = default_end_address);
		std::shared_ptr<hook_t> hook_invalid_memory(protection_type protection, const hook_t::invalid_memory_callback& callback, address_type start_address = default_start_address, address_type end_address = default_end_address);
		std::shared_ptr<hook_t> hook_instruction(hook_instruction_t instruction, const hook_t::instruction_callback& callback, address_type start_address = default_start_address, address_type end_address = default_end_address);

		bool remove_hook(const std::shared_ptr<hook_t>& hook);

		bool map_physical_memory(address_type physical_address, size_type size, protection_type protection);
		bool unmap_physical_memory(address_type physical_address, size_type size);

		bool protect_physical_memory(address_type physical_address, size_type size, protection_type protection);

		bool write_physical_memory(address_type physical_address, const void* buffer, size_type size);
		bool write_physical_memory(address_type physical_address, std::span<const std::uint8_t> buffer);

		bool read_physical_memory(address_type physical_address, void* buffer, size_type size) const;
		bool read_physical_memory(address_type physical_address, std::span<std::uint8_t> buffer) const;

		[[nodiscard]] std::optional<address_type> translate_virtual_address(address_type address) const;

		bool write_register(const guest_register_t& guest_register, const void* value, size_type size);
		bool read_register(const guest_register_t& guest_register, void* value, size_type size) const;

		[[nodiscard]] address_type program_counter() const;
		void set_program_counter(address_type program_counter);

		template <class T>
		[[nodiscard]] T read_physical_memory(const address_type physical_address)
		{
			static_assert(std::is_trivially_copyable_v<T>, "reading non trivially copyable type from physical memory");

			T value = { };

			if (!read_physical_memory(physical_address, &value, sizeof(T)))
			{
				throw std::runtime_error("unable to read physical memory");
			}

			return value;
		}

		template <class T>
		requires !std::is_convertible_v<const T&, std::span<const std::uint8_t>>
		void write_physical_memory(const address_type physical_address, const T& value)
		{
			static_assert(std::is_trivially_copyable_v<T>, "writing non trivially copyable type to physical memory");

			if (!write_physical_memory(physical_address, &value, sizeof(T)))
			{
				throw std::runtime_error("unable to write physical memory");
			}
		}

		template <guest_register_t Register, class T>
		[[nodiscard]] T read_register() const
		{
			const auto processor = virtual_processor();

			return processor.read_register<Register, T>();
		}

		template <guest_register_t Register, class T>
		void write_register(const T& value)
		{
			auto processor = virtual_processor();

			processor.write_register<Register>(value);
		}

	protected:
		bool configure_single_step();
		void reset_guest_exit_state();

		void single_step(guest_virtual_processor_t& processor, vmexit_context_t& context);
		bool handle_page_fault(guest_virtual_processor_t& processor, const vmexit_context_t& context);

		bool handle_exception(guest_virtual_processor_t& processor, vmexit_context_t& context);
		bool handle_memory_access(guest_virtual_processor_t& processor, vmexit_context_t& context);

		void set_block_code_hook_step(const std::shared_ptr<hook_t>& hook);
		void handle_block_hook_overflow(const std::shared_ptr<hook_t>& hook, address_type rip);
		void invoke_block_code_hook_step_callback(const std::shared_ptr<hook_t>& hook, address_type rip,
		                                          std::span<const std::uint8_t> instruction_bytes);
		bool protect_block_code_hook_memory_range(address_type start_address, address_type end_address, bool executable);
		bool memory_process_block_code_hook(guest_virtual_processor_t& processor, vmexit_context_t& context,
		                                    const std::shared_ptr<hook_t>& hook);

		void set_memory_hook_step(guest_virtual_processor_t& processor, vmexit_context_t& context,
		                              const std::shared_ptr<hook_t>& hook, bool& step_handled);
		bool memory_process_memory_hook(guest_virtual_processor_t& processor, vmexit_context_t& context,
		                                const std::shared_ptr<hook_t>& hook, bool& step_handled);

		bool raw_process_invalid_memory_hook(const std::shared_ptr<hook_t>& hook, address_type accessed_address, memory_vmexit_t::access access_type);

		bool handle_cpuid_instruction(guest_virtual_processor_t& processor, vmexit_context_t& context);
		bool handle_rdtsc_instruction(guest_virtual_processor_t& processor, vmexit_context_t& context);

		template <class ...Args>
		std::shared_ptr<hook_t> add_hook(Args&&... arguments)
		{
			const auto hook = std::make_shared<hook_t>(std::forward<Args>(arguments)...);

			hooks_.push_back(hook);

			return hook;
		}

		[[nodiscard]] guest_virtual_processor_t virtual_processor() const;

		bool load_cpu_mode_default_state();

		[[nodiscard]] bool create_default_page_tables();

		std::shared_ptr<guest_partition_t> partition_ = { };
		machine_mode_t mode_ = machine_mode_16;

		// return true = keep in list
		// return false = erase from list
		std::vector<vmexit_callback_t::routine_type> single_step_callbacks_;

		std::vector<std::shared_ptr<hook_t>> hooks_ = { };
	};
}
