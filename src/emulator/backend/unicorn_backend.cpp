#include "unicorn_backend.hpp"

[[nodiscard]] static constexpr uc_prot convert_prot(const emulator_t::protection_type protection)
{
	return static_cast<uc_prot>(protection);
}

[[nodiscard]] static constexpr protection_t convert_access_to_prot(const uc_mem_type access)
{
	switch (access)
	{
	case UC_MEM_READ:
	case UC_MEM_READ_UNMAPPED:
	case UC_MEM_READ_PROT:
	case UC_MEM_READ_AFTER:
		return prot_read;
	case UC_MEM_WRITE:
	case UC_MEM_WRITE_UNMAPPED:
	case UC_MEM_WRITE_PROT:
		return prot_write;
	case UC_MEM_FETCH:
	case UC_MEM_FETCH_UNMAPPED:
	case UC_MEM_FETCH_PROT:
		return prot_execute;
	default:;
	}

	return prot_none;
}

[[nodiscard]] static constexpr uc_hook_type convert_prot_to_inv_mem_hook(const emulator_t::protection_type access)
{
	std::int32_t value = 0;

	if (access & prot_read)
	{
		value |= UC_HOOK_MEM_READ_UNMAPPED;
	}

	if (access & prot_write)
	{
		value |= UC_HOOK_MEM_WRITE_UNMAPPED;
	}

	if (access & prot_execute)
	{
		value |= UC_HOOK_MEM_FETCH_UNMAPPED;
	}

	return static_cast<uc_hook_type>(value);
}

[[nodiscard]] static constexpr uc_hook_type convert_prot_to_mem_access_hook(const emulator_t::protection_type access)
{
	std::int32_t value = 0;

	if (access & prot_read)
	{
		value |= UC_HOOK_MEM_READ;
	}

	if (access & prot_write)
	{
		value |= UC_HOOK_MEM_WRITE;
	}

	if (access & prot_execute)
	{
		value |= UC_HOOK_MEM_FETCH;
	}

	return static_cast<uc_hook_type>(value);
}

[[nodiscard]] static constexpr uc_x86_insn convert_insn(const x86::insn insn)
{
	switch (insn)
	{
	case x86::insn::cpuid:
		return UC_X86_INS_CPUID;
	case x86::insn::rdtsc:
		return UC_X86_INS_RDTSC;
	default:;
	}

	return { };
}

[[nodiscard]] static constexpr uc_x86_reg convert_reg(const x86::reg reg)
{
	switch (reg)
	{
	case x86::reg::rax:
		return UC_X86_REG_RAX;
	case x86::reg::rbx:
		return UC_X86_REG_RBX;
	case x86::reg::rcx:
		return UC_X86_REG_RCX;
	case x86::reg::rdx:
		return UC_X86_REG_RDX;
	case x86::reg::rip:
		return UC_X86_REG_RIP;
	case x86::reg::rsp:
		return UC_X86_REG_RSP;
	case x86::reg::rflags:
		return UC_X86_REG_RFLAGS;
	default:;
	}

	return { };
}

unicorn_hook_t::~unicorn_hook_t()
{
	if (!owning_emulator_ || !native_hook_)
	{
		return;
	}

	const native_emulator_type native_emulator = owning_emulator_->native_backend();

	if (!native_emulator)
	{
		return;
	}

	uc_hook_del(native_emulator, native_hook_);
}

unicorn_emulator_t::unicorn_emulator_t()
{
	const auto error = emulator_err_t{ uc_open(UC_ARCH_X86, UC_MODE_64, &backend_) };

	error.throw_if("unable to create backend engine");
}

unicorn_emulator_t::~unicorn_emulator_t()
{
	if (backend_)
	{
		uc_close(backend_);
	}
}

emulator_err_t unicorn_emulator_t::run_at(const address_type start_address, const address_type end_address)
{
	return emulator_err_t{ uc_emu_start(backend_, start_address, end_address, 0, 0) };
}

emulator_err_t unicorn_emulator_t::map_memory(const address_type address, const size_type size,
                                              const protection_type protection)
{
	const address_type aligned_address = align_down(address, memory_mapping_alignment);
	const size_type aligned_size = align_up(size, memory_mapping_alignment);

	return emulator_err_t{ uc_mem_map(backend_, aligned_address, aligned_size, convert_prot(protection)) };
}

emulator_err_t unicorn_emulator_t::unmap_memory(const address_type address, const size_type size)
{
	const address_type aligned_address = align_down(address, memory_mapping_alignment);
	const size_type aligned_size = align_up(size, memory_mapping_alignment);

	return emulator_err_t{ uc_mem_unmap(backend_, aligned_address, aligned_size) };
}

emulator_err_t unicorn_emulator_t::read_memory(const address_type address, void* const buffer,
                                               const size_type size) const
{
	return emulator_err_t{ uc_mem_read(backend_, address, buffer, size) };
}

emulator_err_t unicorn_emulator_t::write_memory(const address_type address, const void* const buffer,
                                                const size_type size)
{
	return emulator_err_t{ uc_mem_write(backend_, address, buffer, size) };
}

emulator_err_t unicorn_emulator_t::read_register(const x86::reg reg, void* const value) const
{
	return emulator_err_t{ uc_reg_read(backend_, convert_reg(reg), value) };
}

emulator_err_t unicorn_emulator_t::write_register(const x86::reg reg, const void* const value)
{
	return emulator_err_t{ uc_reg_write(backend_, convert_reg(reg), value) };
}

static std::int32_t uc_wrapper_insn_hook([[maybe_unused]] const uc_engine* const engine,
                                         const unicorn_hook_t* const hook)
{
	const auto& hook_callback = hook->callback();

	return std::get<emulator_hook_t::instruction_callback>(hook_callback)();
}

static void uc_wrapper_bb_hook([[maybe_unused]] const uc_engine* const engine,
                               [[maybe_unused]] const std::uint64_t address,
                               [[maybe_unused]] const std::size_t size,
                               const unicorn_hook_t* const hook)
{
	const auto& hook_callback = hook->callback();

	std::get<emulator_hook_t::code_callback>(hook_callback)();
}

static void uc_wrapper_code_hook([[maybe_unused]] const uc_engine* const engine,
                                 [[maybe_unused]] const std::uint64_t address,
                                 [[maybe_unused]] const std::size_t size,
                                 const unicorn_hook_t* const hook)
{
	const auto& hook_callback = hook->callback();

	std::get<emulator_hook_t::code_callback>(hook_callback)();
}

static bool uc_wrapper_invalid_mem_hook([[maybe_unused]] const uc_engine* const engine, const uc_mem_type type,
                                        const std::uint64_t address,
                                        [[maybe_unused]] const std::size_t size,
                                        [[maybe_unused]] const std::uint64_t value,
                                        const unicorn_hook_t* const hook)
{
	const auto& hook_callback = hook->callback();

	const bool handled = std::get<emulator_hook_t::invalid_memory_callback>(hook_callback)(address, convert_access_to_prot(type));

	return handled;
}

static void uc_wrapper_mem_access_hook([[maybe_unused]] const uc_engine* const engine, const uc_mem_type type,
                                       const std::uint64_t address,
                                       [[maybe_unused]] const std::size_t size,
                                       [[maybe_unused]] const std::uint64_t value,
                                       const unicorn_hook_t* const hook)
{
	const auto& hook_callback = hook->callback();

	std::get<emulator_hook_t::memory_access_callback>(hook_callback)(address, convert_access_to_prot(type));
}


std::expected<emulator_t::hook_type, emulator_err_t> unicorn_emulator_t::hook_instruction(
	const x86::insn instruction, const emulator_hook_t::instruction_callback& callback,
	const address_type start_address, const address_type end_address)
{
	const uc_x86_insn insn = convert_insn(instruction);

	return add_native_hook(UC_HOOK_INSN, uc_wrapper_insn_hook, callback, start_address, end_address, insn);
}

std::expected<emulator_t::hook_type, emulator_err_t> unicorn_emulator_t::hook_basic_block(
	const emulator_hook_t::code_callback& callback, const address_type start_address, const address_type end_address)
{
	return add_native_hook(UC_HOOK_BLOCK, uc_wrapper_bb_hook, callback, start_address, end_address);
}

std::expected<emulator_t::hook_type, emulator_err_t> unicorn_emulator_t::hook_code(
	const emulator_hook_t::code_callback& callback, const address_type start_address, const address_type end_address)
{
	return add_native_hook(UC_HOOK_CODE, uc_wrapper_bb_hook, callback, start_address, end_address);
}

std::expected<emulator_t::hook_type, emulator_err_t> unicorn_emulator_t::hook_invalid_memory(
	const emulator_hook_t::invalid_memory_callback& callback, const protection_type monitored_protection,
	const address_type start_address, const address_type end_address)
{
	const uc_hook_type hook_type = convert_prot_to_inv_mem_hook(monitored_protection);

	return add_native_hook(hook_type, uc_wrapper_invalid_mem_hook, callback, start_address, end_address);
}

std::expected<emulator_t::hook_type, emulator_err_t> unicorn_emulator_t::hook_memory(
	const emulator_hook_t::memory_access_callback& callback, const protection_type monitored_protection,
	const address_type start_address, const address_type end_address)
{
	const uc_hook_type hook_type = convert_prot_to_mem_access_hook(monitored_protection);

	return add_native_hook(hook_type, uc_wrapper_mem_access_hook, callback, start_address, end_address);
}

unicorn_emulator_t::backend_type unicorn_emulator_t::native_backend() const
{
	return backend_;
}
