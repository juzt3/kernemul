#include "unicorn_backend.hpp"
#include "../emulator.hpp"
#include "../../kernel/segments.hpp"
#include "../../user/user_memory.hpp"
#include "../../util/logs.hpp"

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

static std::int32_t syscall_insn_hook(uc_engine* uc, void* user_data)
{
	auto* emulator = static_cast<unicorn_emulator_t*>(user_data);

	const auto lstar_result = emulator->read_msr(static_cast<x86::msr>(0xC0000082));
	if (!lstar_result || *lstar_result == 0)
	{
		return 0;
	}
	const auto lstar = *lstar_result;

	std::uint64_t rip = 0;
	uc_reg_read(uc, UC_X86_REG_RIP, &rip);

	std::uint64_t old_rflags = 0;
	uc_reg_read(uc, UC_X86_REG_RFLAGS, &old_rflags);

	const std::uint64_t return_rip = rip + 2;
	uc_reg_write(uc, UC_X86_REG_RCX, &return_rip);
	uc_reg_write(uc, UC_X86_REG_R11, &old_rflags);

	const auto sfmask_result = emulator->read_msr(static_cast<x86::msr>(0xC0000084));
	const std::uint64_t sfmask = sfmask_result ? *sfmask_result : 0;
	const std::uint64_t new_rflags = old_rflags & ~sfmask;
	uc_reg_write(uc, UC_X86_REG_RFLAGS, &new_rflags);

	// compensate for Unicorn's skip-advance (adds insn length after returning 1)
	const std::uint64_t target_rip = lstar - 2;
	uc_reg_write(uc, UC_X86_REG_RIP, &target_rip);

	emulator->write_segment(x86::segment_reg::cs, kernel::kernel_cs_selector, 0, kernel::segment_limit, kernel::kernel_code_attributes);
	emulator->write_segment(x86::segment_reg::ss, kernel::kernel_ds_selector, 0, kernel::segment_limit, kernel::kernel_data_attributes);

	emulator->redirect_pending_ = true;
	uc_emu_stop(uc);

	return 1;
}

static void interrupt_hook_callback(uc_engine* uc, uint32_t intno, void* user_data)
{
	auto* emulator = static_cast<unicorn_emulator_t*>(user_data);

	uint64_t rip = 0;
	uc_reg_read(uc, UC_X86_REG_RIP, &rip);

	static uint64_t intr_count = 0;
	if (++intr_count <= 20)
	{
		GLOBAL_LOG("UC_HOOK_INTR: intno={} rip=0x{:X}", intno, rip);
	}

	// sysret (0F 07) causes #UD because Unicorn doesn't support UC_X86_INS_SYSRET hooks
	if (intno == 6)
	{
		std::uint8_t insn_bytes[2] = {};
		emulator->read_virtual_memory(rip, insn_bytes, sizeof(insn_bytes));

		if (insn_bytes[0] == 0x0F && insn_bytes[1] == 0x07)
		{
			std::uint64_t target_rip = 0;
			uc_reg_read(uc, UC_X86_REG_RCX, &target_rip);

			std::uint64_t saved_rflags = 0;
			uc_reg_read(uc, UC_X86_REG_R11, &saved_rflags);
			uc_reg_write(uc, UC_X86_REG_RFLAGS, &saved_rflags);

			uc_reg_write(uc, UC_X86_REG_RIP, &target_rip);

			const auto star_result = emulator->read_msr(static_cast<x86::msr>(0xC0000081));
			const std::uint64_t star = star_result ? *star_result : 0;
			const auto user_cs = static_cast<std::uint16_t>((star >> 48) + 16);
			const auto user_ss = static_cast<std::uint16_t>((star >> 48) + 8);

			emulator->write_segment(x86::segment_reg::cs, user_cs, 0, kernel::segment_limit, kernel::user_code_attributes);
			emulator->write_segment(x86::segment_reg::ss, user_ss, 0, kernel::segment_limit, kernel::user_data_attributes);
			return;
		}
	}

	// #PF: try demand-commit before delivering through the IDT
	if (intno == 14 && user::memory_manager)
	{
		uint64_t cr2 = 0;
		uc_reg_read(uc, UC_X86_REG_CR2, &cr2);

		if (user::memory_manager->try_demand_commit(cr2)
			|| user::memory_manager->try_handle_guard_page(cr2))
		{
			uc_ctl_flush_tlb(uc);
			return;
		}
	}

	// deliver all other exceptions through the IDT
	uc_x86_mmr idtr = {};
	uc_reg_read(uc, UC_X86_REG_IDTR, &idtr);
	if (idtr.base == 0)
	{
		return;
	}

	std::uint8_t idt_entry[16] = {};
	if (emulator->read_virtual_memory(idtr.base + intno * 16, idt_entry, sizeof(idt_entry)))
	{
		return;
	}

	const auto offset_low = *reinterpret_cast<std::uint16_t*>(idt_entry);
	const auto handler_cs = *reinterpret_cast<std::uint16_t*>(idt_entry + 2);
	const auto offset_mid = *reinterpret_cast<std::uint16_t*>(idt_entry + 6);
	const auto offset_high = *reinterpret_cast<std::uint32_t*>(idt_entry + 8);

	const uint64_t handler =
		static_cast<uint64_t>(offset_low) |
		(static_cast<uint64_t>(offset_mid) << 16) |
		(static_cast<uint64_t>(offset_high) << 32);

	if (handler == 0)
	{
		return;
	}

	uint64_t old_rsp = 0;
	uc_reg_read(uc, UC_X86_REG_RSP, &old_rsp);

	uint64_t old_rflags = 0;
	uc_reg_read(uc, UC_X86_REG_RFLAGS, &old_rflags);

	uc_x86_mmr cs_seg = {};
	uc_reg_read(uc, UC_X86_REG_CS, &cs_seg);

	uc_x86_mmr ss_seg = {};
	uc_reg_read(uc, UC_X86_REG_SS, &ss_seg);

	const bool privilege_change = (cs_seg.selector & 3) != 0;

	uint64_t new_rsp;
	if (privilege_change)
	{
		uc_x86_mmr tr = {};
		uc_reg_read(uc, UC_X86_REG_TR, &tr);
		uint64_t tss_rsp0 = 0;
		if (emulator->read_virtual_memory(tr.base + 4, &tss_rsp0, 8) || tss_rsp0 == 0)
		{
			return;
		}
		new_rsp = tss_rsp0;
	}
	else
	{
		new_rsp = old_rsp;
	}

	// push interrupt frame: SS, RSP, RFLAGS, CS, RIP
	const uint64_t ss_val = static_cast<uint64_t>(ss_seg.selector);
	const uint64_t cs_val = static_cast<uint64_t>(cs_seg.selector);

	new_rsp -= 8;
	emulator->write_virtual_memory(new_rsp, &ss_val, 8);
	new_rsp -= 8;
	emulator->write_virtual_memory(new_rsp, &old_rsp, 8);
	new_rsp -= 8;
	emulator->write_virtual_memory(new_rsp, &old_rflags, 8);
	new_rsp -= 8;
	emulator->write_virtual_memory(new_rsp, &cs_val, 8);
	new_rsp -= 8;
	emulator->write_virtual_memory(new_rsp, &rip, 8);

	constexpr std::uint32_t error_code_vectors[] = { 8, 10, 11, 12, 13, 14, 17, 21, 29, 30 };
	bool needs_error_code = false;
	for (const auto v : error_code_vectors)
	{
		if (v == intno)
		{
			needs_error_code = true;
			break;
		}
	}

	if (needs_error_code)
	{
		uint64_t error_code = 0;
		if (intno == 14)
		{
			// basic #PF error code: U/S from current privilege level
			if (privilege_change)
			{
				error_code |= 4;
			}
		}
		new_rsp -= 8;
		emulator->write_virtual_memory(new_rsp, &error_code, 8);
	}

	uc_reg_write(uc, UC_X86_REG_RSP, &new_rsp);
	uc_reg_write(uc, UC_X86_REG_RIP, &handler);

	emulator->write_segment(x86::segment_reg::cs, handler_cs, 0, kernel::segment_limit, kernel::kernel_code_attributes);

	if (privilege_change)
	{
		emulator->write_segment(x86::segment_reg::ss, kernel::kernel_ds_selector, 0, kernel::segment_limit, kernel::kernel_data_attributes);
	}
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

	uc_hook intr_hook = 0;
	error = emulator_err_t{ uc_hook_add(backend_, &intr_hook, UC_HOOK_INTR,
		reinterpret_cast<void*>(interrupt_hook_callback), this, 1, 0) };
	error.throw_if("unable to add interrupt hook");

	uc_hook sc_hook = 0;
	error = emulator_err_t{ uc_hook_add(backend_, &sc_hook, UC_HOOK_INSN,
		reinterpret_cast<void*>(syscall_insn_hook), this, 1, 0, UC_X86_INS_SYSCALL) };
	error.throw_if("unable to add SYSCALL hook");
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
	stop_requested_ = false;
	redirect_pending_ = false;

	address_type current_address = start_address;

	while (true)
	{
		const auto uc_result = uc_emu_start(backend_, current_address, end_address, 0, 0);

		address_type rip = 0;
		static_cast<void>(read_register(x86::reg::rip, &rip));

		if (redirect_pending_)
		{
			redirect_pending_ = false;
			current_address = rip;
			continue;
		}

		if (rip == thread_return_address)
		{
			return emulator_err_t{ true };
		}

		if (stop_requested_)
		{
			stop_requested_ = false;
			redirect_pending_ = false;
			return emulator_err_t{ false };
		}

		if (uc_result == UC_ERR_EXCEPTION)
		{
			GLOBAL_WARN_LOG("run_at: CPU exception at rip=0x{:X}", rip);
			return emulator_err_t{ false };
		}

		if (uc_result != UC_ERR_OK)
		{
			GLOBAL_WARN_LOG("run_at: uc_emu_start error {} ({}) at rip=0x{:X}",
				static_cast<int>(uc_result), uc_strerror(uc_result), rip);
			return emulator_err_t{ uc_result };
		}

		if (end_address != 0 && rip == end_address)
		{
			return {};
		}

		current_address = rip;
	}
}

emulator_err_t unicorn_emulator_t::stop()
{
	stop_requested_ = true;
	return emulator_err_t{ uc_emu_stop(backend_) };
}

emulator_err_t unicorn_emulator_t::map_physical_memory(const address_type address, const size_type size,
                                                       const protection_type protection)
{
	const address_type aligned_address = align_down(address, page_size);
	const size_type aligned_size = align_up(size, page_size);
	const address_type required_end = aligned_address + aligned_size;

	if (required_end <= mapped_physical_end_)
	{
		return {};
	}

	const address_type map_start = (mapped_physical_end_ > aligned_address)
		? mapped_physical_end_
		: aligned_address;

	const size_type needed = required_end - map_start;
	const size_type map_size = (needed < physical_memory_chunk_size)
		? physical_memory_chunk_size
		: align_up(needed, physical_memory_chunk_size);

	const auto error = emulator_err_t{ uc_mem_map(backend_, map_start, map_size, UC_PROT_ALL) };

	if (error)
	{
		return error;
	}

	mapped_physical_end_ = map_start + map_size;

	return {};
}

emulator_err_t unicorn_emulator_t::unmap_physical_memory(const address_type address, const size_type size)
{
	return {};
}

emulator_err_t unicorn_emulator_t::protect_physical_memory(const address_type address, const size_type size,
                                                           const protection_type protection)
{
	const address_type aligned_address = align_down(address, page_size);
	const size_type aligned_size = align_up(size, page_size);

	return emulator_err_t{ uc_mem_protect(backend_, aligned_address, aligned_size, convert_prot(protection)) };
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

	const auto result = uc_reg_write(backend_, uc_reg, &segment);

	if (result == UC_ERR_OK)
	{
		if (uc_reg == UC_X86_REG_GS)
		{
			std::uint64_t gs_base = base;
			uc_reg_write(backend_, UC_X86_REG_GS_BASE, &gs_base);
		}
		else if (uc_reg == UC_X86_REG_FS)
		{
			std::uint64_t fs_base = base;
			uc_reg_write(backend_, UC_X86_REG_FS_BASE, &fs_base);
		}
	}

	return emulator_err_t{ result };
}

static std::int32_t uc_wrapper_insn_hook(uc_engine* const engine,
                                         const unicorn_hook_t* const hook)
{
	std::uint64_t rip_before = 0;
	uc_reg_read(engine, UC_X86_REG_RIP, &rip_before);

	const auto& hook_callback = hook->callback();
	const auto result = std::get<emulator_hook_t::instruction_callback>(hook_callback)();

	std::uint64_t rip_after = 0;
	uc_reg_read(engine, UC_X86_REG_RIP, &rip_after);

	if (rip_after != rip_before)
	{
		auto* emulator = static_cast<unicorn_emulator_t*>(hook->owning_emulator().get());
		emulator->redirect_pending_ = true;
		uc_emu_stop(engine);
	}

	return result;
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

static void uc_wrapper_execute_redirect_hook(uc_engine* const engine,
                                             const std::uint64_t address,
                                             [[maybe_unused]] const std::uint32_t size,
                                             const unicorn_hook_t* const hook)
{
	const auto& hook_callback = hook->callback();

	std::get<emulator_hook_t::memory_access_callback>(hook_callback)(address, prot_execute);

	std::uint64_t rip = 0;
	uc_reg_read(engine, UC_X86_REG_RIP, &rip);

	if (rip != address)
	{
		auto* emulator = static_cast<unicorn_emulator_t*>(hook->owning_emulator().get());
		emulator->redirect_pending_ = true;
		uc_emu_stop(engine);
	}
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
	if (monitored_protection == prot_execute)
	{
		return add_native_hook(UC_HOOK_CODE, uc_wrapper_execute_redirect_hook, callback, start_address, end_address);
	}

	const uc_hook_type hook_type = convert_prot_to_mem_access_hook(monitored_protection);

	return add_native_hook(hook_type, uc_wrapper_mem_access_hook, callback, start_address, end_address);
}

std::expected<emulator_t::msr_value_type, emulator_err_t> unicorn_emulator_t::read_msr(const x86::msr msr) const
{
	msr_value_type value = { };

	const emulator_err_t error = read_msr_safe(msr, &value);

	if (error)
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
	// Unicorn 2 does not support UC_HOOK_INSN for RDMSR/WRMSR.
	// Guest RDMSR/WRMSR operate on Unicorn's internal MSR state directly.
	// Pre-seed MSR values via write_msr before emulation starts.
	const auto casted_this = std::static_pointer_cast<unicorn_emulator_t>(shared_from_this());
	auto hook = std::make_shared<unicorn_hook_t>(casted_this, uc_hook{}, callback);
	push_hook(hook);
	return hook;
}

unicorn_emulator_t::backend_type unicorn_emulator_t::native_backend() const
{
	return backend_;
}
