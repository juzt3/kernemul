#pragma once
#include "../emulator.hpp"

class unicorn_hook_t : public emulator_hook_t
{
public:
	using owning_emulator_type = std::shared_ptr<class unicorn_emulator_t>;
	using native_emulator_type = uc_engine*;
	using native_hook_type = uc_hook;

	explicit unicorn_hook_t(owning_emulator_type owning_emulator, const native_hook_type native_hook, callback_type callback)
			:	emulator_hook_t(std::move(callback)),
				owning_emulator_(std::move(owning_emulator)),
				native_hook_(native_hook) { }

	~unicorn_hook_t();

	[[nodiscard]] native_hook_type native_hook() const
	{
		return native_hook_;
	}

	void set_native_hook(const native_hook_type native_hook)
	{
		native_hook_ = native_hook;
	}

protected:
	owning_emulator_type owning_emulator_;
	native_hook_type native_hook_;
};

class unicorn_emulator_t : public emulator_t
{
public:
	using backend_type = uc_engine*;
	using msr_value_type = std::uint64_t;

	unicorn_emulator_t();
	~unicorn_emulator_t();

	[[nodiscard]] emulator_err_t run_at(address_type start_address, address_type end_address) override;

	[[nodiscard]] emulator_err_t map_physical_memory(address_type address, size_type size, protection_type protection) override;
	[[nodiscard]] emulator_err_t unmap_physical_memory(address_type address, size_type size) override;

	[[nodiscard]] emulator_err_t read_physical_memory(address_type address, void* buffer, size_type size) const override;
	[[nodiscard]] emulator_err_t write_physical_memory(address_type address, const void* buffer, size_type size) override;

	[[nodiscard]] emulator_err_t read_register(x86::register_t reg, void* value) const override;
	[[nodiscard]] emulator_err_t write_register(x86::register_t reg, const void* value) override;

	std::expected<hook_type, emulator_err_t> hook_instruction(x86::insn instruction,
	                                                          const emulator_hook_t::instruction_callback& callback, address_type start_address,
	                                                          address_type end_address) override;

	std::expected<hook_type, emulator_err_t> hook_basic_block(const emulator_hook_t::code_callback& callback,
	                                                          address_type start_address, address_type end_address) override;

	std::expected<hook_type, emulator_err_t> hook_code(const emulator_hook_t::code_callback& callback,
	                                                   address_type start_address, address_type end_address) override;

	std::expected<hook_type, emulator_err_t> hook_invalid_memory(
		const emulator_hook_t::invalid_memory_callback& callback, protection_type monitored_protection,
		address_type start_address, address_type end_address) override;

	std::expected<hook_type, emulator_err_t> hook_memory(const emulator_hook_t::memory_access_callback& callback,
	                                                     protection_type monitored_protection,
	                                                     address_type start_address, address_type end_address) override;


	[[nodiscard]] msr_value_type read_msr(x86::msr msr) const;
	void write_msr(x86::msr msr, msr_value_type value);

	[[nodiscard]] backend_type native_backend() const;

protected:
	[[nodiscard]] emulator_err_t read_msr_safe(x86::msr msr, msr_value_type* value) const;
	emulator_err_t write_msr_safe(x86::msr msr, msr_value_type value);

	template <class ...Args>
	[[nodiscard]] std::expected<hook_type, emulator_err_t> add_native_hook(
		const std::int32_t hook_type, void* const uc_callback_wrapper, const emulator_hook_t::callback_type& callback,
		const address_type start_address, const address_type end_address, Args... arguments)
	{
		const auto casted_this = std::static_pointer_cast<unicorn_emulator_t>(shared_from_this());

		auto hook = std::make_shared<unicorn_hook_t>(casted_this, uc_hook{}, callback);

		uc_hook native_hook = 0;

		const emulator_err_t error(uc_hook_add(backend_, &native_hook, hook_type, uc_callback_wrapper, hook.get(),
		                                       start_address, end_address, arguments...));

		if (error)
		{
			return std::unexpected(error);
		}

		hook->set_native_hook(native_hook);

		push_hook(hook);

		return hook;
	}

	backend_type backend_ = nullptr;
};
