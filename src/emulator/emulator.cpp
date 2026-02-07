#include "emulator.hpp"
#include <stdexcept>
#include <format>

void emulator_err_t::throw_if(std::string_view info) const
{
	if (*this)
	{
		throw std::runtime_error(std::format("{}: '{}'", info, to_string()));
	}
}

emulator_t::emulator_t()
{
	emulator_err_t error = uc_open(UC_ARCH_X86, UC_MODE_64, &engine_);

	error.throw_if("unable to create emulation engine");

	constexpr address_type stack_base_address = 0x10000;
	constexpr size_type stack_size = 0x10000;

	constexpr address_type starting_rsp_value = stack_base_address + stack_size - 8;

	error = map_memory(stack_base_address, stack_size, UC_PROT_READ | UC_PROT_WRITE);

	error.throw_if("unable to map stack");

	error = write_register(x86::reg::rsp, &starting_rsp_value);

	error.throw_if("unable to set stack pointer");

	error = write_memory(starting_rsp_value, &thread_return_address, sizeof(thread_return_address));

	error.throw_if("unable to set return address");
}

emulator_t::~emulator_t()
{
	uc_close(engine_);
}

emulator_err_t emulator_t::run_at(const address_type start_address, const address_type end_address) const
{
	return uc_emu_start(engine_, start_address, end_address, 0, 0);
}

emulator_err_t emulator_t::map_memory(const address_type address, const size_type size, const protection_type protection) const
{
	const size_type aligned_size = align_memory_map_size(size);

	return uc_mem_map(engine_, address, aligned_size, protection);
}

emulator_err_t emulator_t::unmap_memory(const address_type address, const size_type size) const
{
	const size_type aligned_size = align_memory_map_size(size);

	return uc_mem_unmap(engine_, address, aligned_size);
}

emulator_err_t emulator_t::read_memory(const address_type address, void* const buffer, const size_type size) const
{
	return uc_mem_read(engine_, address, buffer, size);
}

emulator_err_t emulator_t::write_memory(const address_type address, const void* const buffer, const size_type size) const
{
	return uc_mem_write(engine_, address, buffer, size);
}

emulator_err_t emulator_t::write_memory(const address_type address, const std::span<const std::uint8_t> buffer) const
{
	return write_memory(address, buffer.data(), buffer.size());
}

emulator_err_t emulator_t::load_memory(const address_type address, const std::span<const std::uint8_t> buffer,
                                       const protection_type protection) const
{
	emulator_err_t error = map_memory(address, buffer.size(), protection);

	if (error)
	{
		return error;
	}

	error = write_memory(address, buffer);

	if (error)
	{
		(void)unmap_memory(address, buffer.size());
	}

	return error;
}

emulator_err_t emulator_t::read_register(const emulator_reg_t reg, void* const value) const
{
	return uc_reg_read(engine_, reg.value(), value);
}

emulator_err_t emulator_t::write_register(const emulator_reg_t reg, const void* const value) const
{
	return uc_reg_write(engine_, reg.value(), value);
}
