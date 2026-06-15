#include "unicorn_backend.hpp"
#include "../emulator.hpp"

#include <ia32-doc/ia32.hpp>

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

[[nodiscard]] static constexpr uc_x86_reg convert_reg(const x86::register_t reg)
{
#define CASE_REG(id_name, uc_name) case x86::register_t::id_type::id_name: return UC_X86_REG_##uc_name;

	switch (reg.id)
	{
		CASE_REG(cr0, CR0)
		CASE_REG(cr2, CR2)
		CASE_REG(cr3, CR3)
		CASE_REG(cr4, CR4)
		CASE_REG(cr8, CR8)
		//
		CASE_REG(rip, RIP)
		CASE_REG(rflags, RFLAGS)
		//
		CASE_REG(rax, RAX)
		CASE_REG(rcx, RCX)
		CASE_REG(rdx, RDX)
		CASE_REG(rbx, RBX)
		CASE_REG(rsp, RSP)
		CASE_REG(rbp, RBP)
		CASE_REG(rsi, RSI)
		CASE_REG(rdi, RDI)
		CASE_REG(r8, R8)
		CASE_REG(r9, R9)
		CASE_REG(r10, R10)
		CASE_REG(r11, R11)
		CASE_REG(r12, R12)
		CASE_REG(r13, R13)
		CASE_REG(r14, R14)
		CASE_REG(r15, R15)
		//
		CASE_REG(xmm0, XMM0)
		CASE_REG(xmm1, XMM1)
		CASE_REG(xmm2, XMM2)
		CASE_REG(xmm3, XMM3)
		CASE_REG(xmm4, XMM4)
		CASE_REG(xmm5, XMM5)
		CASE_REG(xmm6, XMM6)
		CASE_REG(xmm7, XMM7)
		CASE_REG(xmm8, XMM8)
		CASE_REG(xmm9, XMM9)
		CASE_REG(xmm10, XMM10)
		CASE_REG(xmm11, XMM11)
		CASE_REG(xmm12, XMM12)
		CASE_REG(xmm13, XMM13)
		CASE_REG(xmm14, XMM14)
		CASE_REG(xmm15, XMM15)
		default:;
	}

	return { };
}

static void enable_ia32e_mode(unicorn_emulator_t& emulator)
{
	ia32_efer_register efer = { .flags = *emulator.read_msr(x86::msr::efer) };

	efer.ia32e_mode_enable = 1;

	static_cast<void>(emulator.write_msr(x86::msr::efer, efer.flags));
}

static void enable_protected_mode(emulator_t& emulator)
{
	cr0 current_cr0 = emulator.read_register<x86::reg::cr0, cr0>();

	current_cr0.protection_enable = 1;

	emulator.write_register<x86::reg::cr0>(current_cr0);
}

static void enable_paging(emulator_t& emulator)
{
	cr0 current_cr0 = emulator.read_register<x86::reg::cr0, cr0>();

	current_cr0.paging_enable = 1;

	emulator.write_register<x86::reg::cr0>(current_cr0);
}

static void enable_physical_address_extension(emulator_t& emulator)
{
	cr4 current_cr4 = emulator.read_register<x86::reg::cr4, cr4>();

	current_cr4.physical_address_extension = 1;

	emulator.write_register<x86::reg::cr4>(current_cr4);
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
	auto error = emulator_err_t{ uc_open(UC_ARCH_X86, UC_MODE_64, &backend_) };

	error.throw_if("unable to create backend engine");

	set_up_page_tables();

	enable_protected_mode(*this);

	enable_paging(*this);
	enable_physical_address_extension(*this);

	enable_ia32e_mode(*this);

	error = emulator_err_t{ uc_ctl_tlb_mode(backend_, UC_TLB_CPU) };

	error.throw_if("unable to set TLB mode");

	error = emulator_err_t{ uc_ctl_flush_tlb(backend_) };

	error.throw_if("unable to flush TLB");
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

emulator_err_t unicorn_emulator_t::stop()
{
	return emulator_err_t{ uc_emu_stop(backend_) };
}

emulator_err_t unicorn_emulator_t::map_physical_memory(const address_type address, const size_type size,
                                                       const protection_type protection)
{
	const address_type aligned_address = align_down(address, page_size);
	const size_type aligned_size = align_up(size, page_size);

	return emulator_err_t{ uc_mem_map(backend_, aligned_address, aligned_size, convert_prot(protection)) };
}

emulator_err_t unicorn_emulator_t::unmap_physical_memory(const address_type address, const size_type size)
{
	const address_type aligned_address = align_down(address, page_size);
	const size_type aligned_size = align_up(size, page_size);

	return emulator_err_t{ uc_mem_unmap(backend_, aligned_address, aligned_size) };
}

emulator_err_t unicorn_emulator_t::read_physical_memory(const address_type address, void* const buffer,
                                               const size_type size) const
{
	return emulator_err_t{ uc_mem_read(backend_, address, buffer, size) };
}

emulator_err_t unicorn_emulator_t::write_physical_memory(const address_type address, const void* const buffer,
                                                const size_type size)
{
	return emulator_err_t{ uc_mem_write(backend_, address, buffer, size) };
}

emulator_err_t unicorn_emulator_t::read_register(const x86::register_t reg, void* const value) const
{
	return emulator_err_t{ uc_reg_read(backend_, convert_reg(reg), value) };
}

emulator_err_t unicorn_emulator_t::write_register(const x86::register_t reg, const void* const value)
{
	return emulator_err_t{ uc_reg_write(backend_, convert_reg(reg), value) };
}

emulator_err_t unicorn_emulator_t::write_idt(const address_type base, const size_type limit)
{
	const uc_x86_mmr idtr = {
		.selector = 0,
		.base = base,
		.limit = static_cast<std::uint16_t>(limit),
		.flags = 0
	};

	return emulator_err_t{ uc_reg_write(backend_, UC_X86_REG_IDTR, &idtr) };
}

emulator_err_t unicorn_emulator_t::write_gdt(const address_type base, const size_type limit)
{
	const uc_x86_mmr gdtr = {
		.selector = 0,
		.base = base,
		.limit = static_cast<std::uint16_t>(limit),
		.flags = 0
	};

	return emulator_err_t{ uc_reg_write(backend_, UC_X86_REG_GDTR, &gdtr) };
}

emulator_err_t unicorn_emulator_t::write_tr(const uint16_t selector, const address_type base, const size_type limit, const uint16_t attributes)
{
	const uc_x86_mmr tr = {
		.selector = selector,
		.base = base,
		.limit = static_cast<std::uint16_t>(limit),
		.flags = attributes
	};

	return emulator_err_t{ uc_reg_write(backend_, UC_X86_REG_TR, &tr) };
}

emulator_err_t unicorn_emulator_t::write_segment(const x86::segment_reg seg, const uint16_t selector, const address_type base, const uint32_t limit, const uint16_t attributes)
{
	static constexpr std::int32_t segment_map[] = {
		UC_X86_REG_CS,
		UC_X86_REG_SS,
		UC_X86_REG_DS,
		UC_X86_REG_ES,
		UC_X86_REG_FS,
		UC_X86_REG_GS
	};

	const auto uc_reg = segment_map[static_cast<std::uint8_t>(seg)];

	const uc_x86_mmr segment = {
		.selector = selector,
		.base = base,
		.limit = static_cast<std::uint32_t>(limit),
		.flags = attributes
	};

	return emulator_err_t{ uc_reg_write(backend_, uc_reg, &segment) };
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

std::expected<emulator_t::msr_value_type, emulator_err_t> unicorn_emulator_t::read_msr(const x86::msr msr) const
{
	msr_value_type value = { };

	const emulator_err_t error = read_msr_safe(msr, &value);

	if (!error)
	{
		return std::unexpected(error);
	}

	return value;
}

emulator_err_t unicorn_emulator_t::write_msr(const x86::msr msr, const msr_value_type value)
{
	return write_msr_safe(msr, value);
}

emulator_err_t unicorn_emulator_t::read_msr_safe(const x86::msr msr, msr_value_type* const value) const
{
	uc_x86_msr uc_msr = {
		.rid = static_cast<std::uint32_t>(msr),
		.value = 0
	};

	const emulator_err_t error(uc_reg_read(backend_, UC_X86_REG_MSR, &uc_msr));

	*value = uc_msr.value;

	return error;
}

emulator_err_t unicorn_emulator_t::write_msr_safe(const x86::msr msr, const msr_value_type value)
{
	const uc_x86_msr uc_msr = {
		.rid = static_cast<std::uint32_t>(msr),
		.value = value
	};

	return emulator_err_t{ uc_reg_write(backend_, UC_X86_REG_MSR, &uc_msr) };
}

std::expected<emulator_t::hook_type, emulator_err_t> unicorn_emulator_t::hook_msr(
	const emulator_hook_t::msr_callback& callback)
{
	return std::unexpected(emulator_err_t{ false });
}

unicorn_emulator_t::backend_type unicorn_emulator_t::native_backend() const
{
	return backend_;
}
