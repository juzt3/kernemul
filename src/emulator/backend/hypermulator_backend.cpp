#include "hypermulator_backend.hpp"

[[nodiscard]] static constexpr hm::protection_t convert_prot(const emulator_t::protection_type protection)
{
	return static_cast<hm::protection_t>(protection);
}

[[nodiscard]] static constexpr protection_t convert_access_to_prot(const hm::memory_vmexit_t::access_t access)
{
	switch (access)
	{
	case hm::memory_vmexit_t::access_t::read:
		return prot_read;
	case hm::memory_vmexit_t::access_t::write:
		return prot_write;
	case hm::memory_vmexit_t::access_t::execute:
		return prot_execute;
	}

	return prot_none;
}

[[nodiscard]] static constexpr hm::guest_register_t convert_reg(const x86::register_t reg)
{
#define CASE_REG(id_name) case x86::register_t::id_type::id_name: return hm::reg::##id_name;

	switch (reg.id)
	{
		CASE_REG(cr0)
		CASE_REG(cr2)
		CASE_REG(cr3)
		CASE_REG(cr4)
		//
		CASE_REG(rip)
		CASE_REG(rflags)
		//
		CASE_REG(rax)
		CASE_REG(rcx)
		CASE_REG(rdx)
		CASE_REG(rbx)
		CASE_REG(rsp)
		CASE_REG(rbp)
		CASE_REG(rsi)
		CASE_REG(rdi)
		CASE_REG(r8)
		CASE_REG(r9)
		CASE_REG(r10)
		CASE_REG(r11)
		CASE_REG(r12)
		CASE_REG(r13)
		CASE_REG(r14)
		CASE_REG(r15)
		default:;
	}

	return { };
}

[[nodiscard]] static constexpr hm::hook_instruction_t convert_hook_insn(const x86::insn insn)
{
	switch (insn)
	{
	case x86::insn::cpuid:
		return hm::hook_instruction_t::cpuid;
	case x86::insn::rdtsc:
		return hm::hook_instruction_t::rdtsc;
	default:;
	}

	return { };
}

hypermulator_hook_t::~hypermulator_hook_t()
{
	if (native_emulator_ && native_hook_)
	{
		native_emulator_->remove_hook(native_hook_);
	}
}

hypermulator_t::hypermulator_t()
		:	backend_(std::make_shared<hm::emulator_t>(hm::machine_mode_64))
{

}

emulator_err_t hypermulator_t::run_at(const address_type start_address, const address_type end_address)
{
	return emulator_err_t{ backend_->run_at(start_address, end_address) };
}

emulator_err_t hypermulator_t::map_memory(const address_type address, const size_type size,
                                          const protection_type protection)
{
	const address_type aligned_address = align_down(address, memory_mapping_alignment);
	const size_type aligned_size = align_up(size, memory_mapping_alignment);

	return emulator_err_t{ backend_->map_physical_memory(aligned_address, aligned_size, convert_prot(protection)) };
}

emulator_err_t hypermulator_t::unmap_memory(const address_type address, const size_type size)
{
	const address_type aligned_address = align_down(address, memory_mapping_alignment);
	const size_type aligned_size = align_up(size, memory_mapping_alignment);

	return emulator_err_t{ backend_->unmap_physical_memory(aligned_address, aligned_size) };
}

emulator_err_t hypermulator_t::read_memory(const address_type address, void* const buffer, const size_type size) const
{
	return emulator_err_t{ backend_->read_physical_memory(address, buffer, size) };
}

emulator_err_t hypermulator_t::write_memory(const address_type address, const void* const buffer, const size_type size)
{
	return emulator_err_t{ backend_->write_physical_memory(address, buffer, size) };
}

emulator_err_t hypermulator_t::read_register(const x86::register_t reg, void* const value) const
{
	const hm::guest_register_t guest_reg = convert_reg(reg);

	return emulator_err_t{ backend_->read_register(guest_reg, value, guest_reg.size) };
}

emulator_err_t hypermulator_t::write_register(const x86::register_t reg, const void* const value)
{
	const hm::guest_register_t guest_reg = convert_reg(reg);

	return emulator_err_t{ backend_->write_register(guest_reg, value, guest_reg.size) };
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::hook_instruction(
	const x86::insn instruction, const emulator_hook_t::instruction_callback& callback,
	const address_type start_address,
	const address_type end_address)
{
	const hm::hook_instruction_t insn = convert_hook_insn(instruction);
	const auto native_hook = backend_->hook_instruction(insn, callback, start_address, end_address);

	return add_native_hook(native_hook, callback);
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::hook_basic_block(
	const emulator_hook_t::code_callback& callback, const address_type start_address, const address_type end_address)
{
	const auto native_hook = backend_->hook_basic_block(callback, start_address, end_address);

	return add_native_hook(native_hook, callback);
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::hook_code(
	const emulator_hook_t::code_callback& callback, const address_type start_address, const address_type end_address)
{
	const auto native_hook = backend_->hook_code(callback, start_address, end_address);

	return add_native_hook(native_hook, callback);
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::hook_invalid_memory(
	const emulator_hook_t::invalid_memory_callback& callback, const protection_type monitored_protection,
	const address_type start_address, const address_type end_address)
{
	const auto prot = convert_prot(monitored_protection);

	const auto native_hook = backend_->hook_invalid_memory(prot,
		[callback](const address_type faulting_address, const hm::memory_vmexit_t::access_t access)
		{
			const protection_t converted_access = convert_access_to_prot(access);

			return callback(faulting_address, converted_access);
		},
		start_address,
		end_address
	);

	return add_native_hook(native_hook, callback);
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::hook_memory(
	const emulator_hook_t::memory_access_callback& callback, const protection_type monitored_protection,
	const address_type start_address, const address_type end_address)
{
	const auto prot = convert_prot(monitored_protection);

	const auto native_hook = backend_->hook_memory(prot,
		[callback](const address_type faulting_address, const hm::memory_vmexit_t::access_t access)
		{
			const protection_t converted_access = convert_access_to_prot(access);

			return callback(faulting_address, converted_access);
		},
		start_address,
		end_address
	);

	return add_native_hook(native_hook, callback);
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::add_native_hook(
	const std::shared_ptr<hm::hook_t>& native_hook, const emulator_hook_t::callback_type& callback)
{
	if (native_hook)
	{
		return add_hook<hypermulator_hook_t>(backend_, native_hook, callback);
	}

	return std::unexpected(emulator_err_t{ static_cast<bool>(native_hook) });
}
