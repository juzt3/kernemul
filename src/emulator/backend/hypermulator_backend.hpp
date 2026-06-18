#pragma once
#include "../emulator.hpp"
#include <hypermulator/emulator/emulator.hpp>

class hypermulator_hook_t : public emulator_hook_t
{
public:
	using native_emulator_type = std::shared_ptr<hm::emulator_t>;
	using native_hook_type = std::shared_ptr<hm::hook_t>;

	explicit hypermulator_hook_t(native_emulator_type native_emulator, std::span<const native_hook_type> native_hooks, callback_type callback)
			:	emulator_hook_t(std::move(callback)),
				native_emulator_(std::move(native_emulator)),
				native_hooks_(native_hooks.begin(), native_hooks.end()) { }

	~hypermulator_hook_t();

protected:
	native_emulator_type native_emulator_;
	std::vector<native_hook_type> native_hooks_;
};

class hypermulator_t : public emulator_t
{
public:
	hypermulator_t();

	[[nodiscard]] emulator_err_t run_at(address_type start_address, address_type end_address) override;
	[[nodiscard]] emulator_err_t stop() override;

	[[nodiscard]] emulator_err_t map_physical_memory(address_type address, size_type size, protection_type protection) override;
	[[nodiscard]] emulator_err_t unmap_physical_memory(address_type address, size_type size) override;
	[[nodiscard]] emulator_err_t protect_physical_memory(address_type address, size_type size, protection_type protection) override;

	[[nodiscard]] emulator_err_t read_physical_memory(address_type address, void* buffer, size_type size) const override;
	[[nodiscard]] emulator_err_t write_physical_memory(address_type address, const void* buffer, size_type size) override;

	[[nodiscard]] emulator_err_t read_register(x86::register_t reg, void* value) const override;
	[[nodiscard]] emulator_err_t write_register(x86::register_t reg, const void* value) override;

	[[nodiscard]] emulator_err_t write_idt(address_type base, size_type limit) override;
	[[nodiscard]] emulator_err_t write_gdt(address_type base, size_type limit) override;
	[[nodiscard]] emulator_err_t write_tr(uint16_t selector, address_type base, size_type limit, uint16_t attributes) override;
	[[nodiscard]] emulator_err_t write_segment(x86::segment_reg seg, uint16_t selector, address_type base, uint32_t limit, uint16_t attributes) override;

	[[nodiscard]] std::expected<msr_value_type, emulator_err_t> read_msr(x86::msr msr) const override;
	[[nodiscard]] emulator_err_t write_msr(x86::msr msr, msr_value_type value) override;

	std::expected<hook_type, emulator_err_t> hook_instruction(x86::insn instruction,
	                                                          const emulator_hook_t::instruction_callback& callback, address_type start_address,
	                                                          address_type end_address) override;

	std::expected<hook_type, emulator_err_t> hook_basic_block(const emulator_hook_t::code_callback& callback,
	                                                          address_type start_address, address_type end_address) override;

	std::expected<hook_type, emulator_err_t> hook_code(const emulator_hook_t::code_callback& callback, address_type start_address,
	                                                   address_type end_address) override;

	std::expected<hook_type, emulator_err_t> hook_msr(const emulator_hook_t::msr_callback& callback) override;

	emulator_err_t monitor_msr(std::uint32_t msr_index) override;

	std::expected<hook_type, emulator_err_t> hook_invalid_memory(const emulator_hook_t::invalid_memory_callback& callback,
	                                                             protection_type monitored_protection, address_type start_address, address_type end_address) override;

	std::expected<hook_type, emulator_err_t> hook_memory(const emulator_hook_t::memory_access_callback& callback,
	                                                     protection_type monitored_protection, address_type start_address, address_type end_address) override;

	void cancel_pending_single_step() override;

protected:
	using virtual_hook_creation_callback = std::function<hypermulator_hook_t::native_hook_type(address_type start_physical_address, address_type end_physical_address)>;

	[[nodiscard]] std::vector<hypermulator_hook_t::native_hook_type> wrap_virtual_hook_creation(
		const virtual_hook_creation_callback& callback, address_type start_address,
		address_type end_address);

	[[nodiscard]] std::expected<hook_type, emulator_err_t> add_native_hook(
		std::span<const hypermulator_hook_t::native_hook_type> native_hooks, const emulator_hook_t::callback_type& callback);

protected:
	std::shared_ptr<hm::emulator_t> backend_;
};
