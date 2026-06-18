#include "hypermulator_backend.hpp"

[[nodiscard]] static constexpr hm::protection_t convert_prot(const emulator_t::protection_type protection)
{
	return static_cast<hm::protection_t>(protection);
}

[[nodiscard]] static constexpr protection_t convert_access_to_prot(const hm::memory_vmexit_t::access access)
{
	switch (access)
	{
	case hm::memory_vmexit_t::access::read:
		return prot_read;
	case hm::memory_vmexit_t::access::write:
		return prot_write;
	case hm::memory_vmexit_t::access::execute:
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
		CASE_REG(cr8)
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
		//
		CASE_REG(xmm0)
		CASE_REG(xmm1)
		CASE_REG(xmm2)
		CASE_REG(xmm3)
		CASE_REG(xmm4)
		CASE_REG(xmm5)
		CASE_REG(xmm6)
		CASE_REG(xmm7)
		CASE_REG(xmm8)
		CASE_REG(xmm9)
		CASE_REG(xmm10)
		CASE_REG(xmm11)
		CASE_REG(xmm12)
		CASE_REG(xmm13)
		CASE_REG(xmm14)
		CASE_REG(xmm15)
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
	if (native_emulator_ && !native_hooks_.empty())
	{
		for (const auto& native_hook : native_hooks_)
		{
			native_emulator_->remove_hook(native_hook);
		}
	}
}

hypermulator_t::hypermulator_t()
		:	backend_(std::make_shared<hm::emulator_t>(hm::machine_mode_64))
{
	set_up_page_tables();
}

emulator_err_t hypermulator_t::run_at(const address_type start_address, const address_type end_address)
{
	return emulator_err_t{ backend_->run_at(start_address, end_address) };
}

emulator_err_t hypermulator_t::stop()
{
	backend_->stop();

	return emulator_err_t{ };
}

emulator_err_t hypermulator_t::map_physical_memory(const address_type address, const size_type size,
                                                   const protection_type protection)
{
	const address_type aligned_address = align_down(address, page_size);
	const size_type aligned_size = align_up(size, page_size);

	return emulator_err_t{ backend_->map_physical_memory(aligned_address, aligned_size, convert_prot(protection)) };
}

emulator_err_t hypermulator_t::unmap_physical_memory(const address_type address, const size_type size)
{
	const address_type aligned_address = align_down(address, page_size);
	const size_type aligned_size = align_up(size, page_size);

	return emulator_err_t{ backend_->unmap_physical_memory(aligned_address, aligned_size) };
}

emulator_err_t hypermulator_t::protect_physical_memory(const address_type address, const size_type size, const protection_type protection)
{
	const address_type aligned_address = align_down(address, page_size);
	const size_type aligned_size = align_up(size, page_size);

	return emulator_err_t{ backend_->protect_physical_memory(aligned_address, aligned_size, protection) };
}

emulator_err_t hypermulator_t::read_physical_memory(const address_type address, void* const buffer, const size_type size) const
{
	return emulator_err_t{ backend_->read_physical_memory(address, buffer, size) };
}

emulator_err_t hypermulator_t::write_physical_memory(const address_type address, const void* const buffer, const size_type size)
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

emulator_err_t hypermulator_t::write_idt(const address_type base, const size_type limit)
{
	const hm::guest_table_register_t idtr = {
		.pad = { },
		.limit = static_cast<std::uint16_t>(limit),
		.base = base
	};

	return emulator_err_t{ backend_->write_register(hm::reg::idtr, &idtr, sizeof(idtr)) };
}

emulator_err_t hypermulator_t::write_gdt(const address_type base, const size_type limit)
{
	const hm::guest_table_register_t gdtr = {
		.pad = { },
		.limit = static_cast<std::uint16_t>(limit),
		.base = base
	};

	return emulator_err_t{ backend_->write_register(hm::reg::gdtr, &gdtr, sizeof(gdtr)) };
}

emulator_err_t hypermulator_t::write_tr(const uint16_t selector, const address_type base, const size_type limit, const uint16_t attributes)
{
	const hm::guest_segment_register_t tr = {
		.base = base,
		.limit = static_cast<std::uint32_t>(limit),
		.selector = selector,
		.attributes = attributes
	};

	return emulator_err_t{ backend_->write_register(hm::reg::tr, &tr, sizeof(tr)) };
}

emulator_err_t hypermulator_t::write_segment(const x86::segment_reg seg, const uint16_t selector, const address_type base, const uint32_t limit, const uint16_t attributes)
{
	static constexpr std::array segment_map = {
		hm::reg::cs,
		hm::reg::ss,
		hm::reg::ds,
		hm::reg::es,
		hm::reg::fs,
		hm::reg::gs
	};

	const auto& guest_reg = segment_map[static_cast<std::uint8_t>(seg)];

	const hm::guest_segment_register_t segment = {
		.base = base,
		.limit = limit,
		.selector = selector,
		.attributes = attributes
	};

	return emulator_err_t{ backend_->write_register(guest_reg, &segment, sizeof(segment)) };
}

static hm::guest_register_t msr_to_hm_reg(const x86::msr msr)
{
	switch (msr)
	{
	case x86::msr::efer:   return hm::reg::efer;
	case x86::msr::star:   return hm::reg::star;
	case x86::msr::lstar:  return hm::reg::lstar;
	case x86::msr::cstar:  return hm::reg::cstar;
	case x86::msr::sfmask: return hm::reg::sfmask;
	}

	throw std::runtime_error("unsupported msr");
}

std::expected<emulator_t::msr_value_type, emulator_err_t> hypermulator_t::read_msr(const x86::msr msr) const
{
	const auto reg = msr_to_hm_reg(msr);

	msr_value_type value = 0;

	if (!backend_->read_register(reg, &value, sizeof(value)))
	{
		return std::unexpected(emulator_err_t{ false });
	}

	return value;
}

emulator_err_t hypermulator_t::write_msr(const x86::msr msr, const msr_value_type value)
{
	const auto reg = msr_to_hm_reg(msr);
	return emulator_err_t{ backend_->write_register(reg, &value, sizeof(value)) };
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::hook_instruction(
	const x86::insn instruction, const emulator_hook_t::instruction_callback& callback,
	const address_type start_address,
	const address_type end_address)
{
	const hm::hook_instruction_t insn = convert_hook_insn(instruction);
	const auto native_hook = backend_->hook_instruction(insn, callback, start_address, end_address);

	return add_native_hook(std::array{ native_hook }, callback);
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::hook_basic_block(
	const emulator_hook_t::code_callback& callback, const address_type start_address, const address_type end_address)
{
	const auto native_hooks = wrap_virtual_hook_creation(
		[this, callback](const address_type start_physical_address, const address_type end_physical_address) -> hypermulator_hook_t::native_hook_type
		{
			return backend_->hook_basic_block(callback, start_physical_address, end_physical_address);
		},
		start_address,
		end_address
	);

	return add_native_hook(native_hooks, callback);
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::hook_code(
	const emulator_hook_t::code_callback& callback, const address_type start_address, const address_type end_address)
{
	const auto native_hooks = wrap_virtual_hook_creation(
		[this, callback](const address_type start_physical_address, const address_type end_physical_address) -> hypermulator_hook_t::native_hook_type
		{
			return backend_->hook_code(callback, start_physical_address, end_physical_address);
		},
		start_address,
		end_address
	);

	return add_native_hook(native_hooks, callback);
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::hook_msr(
	const emulator_hook_t::msr_callback& callback)
{
	const auto native_hook = backend_->hook_msr(callback);

	return add_native_hook(std::array{ native_hook }, callback);
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::hook_invalid_memory(
	const emulator_hook_t::invalid_memory_callback& callback, const protection_type monitored_protection,
	const address_type start_address, const address_type end_address)
{
	const auto prot = convert_prot(monitored_protection);

	const auto native_hook = backend_->hook_invalid_memory(prot,
		[callback](const address_type faulting_address, const hm::memory_vmexit_t::access access)
		{
			const protection_t converted_access = convert_access_to_prot(access);

			return callback(faulting_address, converted_access);
		},
		start_address,
		end_address
	);

	return add_native_hook(std::array{ native_hook }, callback);
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::hook_memory(
	const emulator_hook_t::memory_access_callback& callback, const protection_type monitored_protection,
	const address_type start_address, const address_type end_address)
{
	const auto prot = convert_prot(monitored_protection);

	const auto native_hooks = wrap_virtual_hook_creation(
		[this, callback, prot](const address_type start_physical_address, const address_type end_physical_address) -> hypermulator_hook_t::native_hook_type
		{
			return backend_->hook_memory(prot,
				[callback](const address_type faulting_address, const hm::memory_vmexit_t::access access)
				{
					const protection_t converted_access = convert_access_to_prot(access);

					return callback(faulting_address, converted_access);
				},
				start_physical_address,
				end_physical_address
			);
		},
		start_address,
		end_address
	);

	return add_native_hook(native_hooks, callback);
}

emulator_err_t hypermulator_t::monitor_msr(const std::uint32_t msr_index)
{
	return emulator_err_t{ backend_->monitor_msr(msr_index) };
}

void hypermulator_t::cancel_pending_single_step()
{
	backend_->cancel_pending_single_step();
}

std::vector<hypermulator_hook_t::native_hook_type> hypermulator_t::wrap_virtual_hook_creation(
	const virtual_hook_creation_callback& callback, const address_type start_address, const address_type end_address)
{
	bool failed = false;

	std::vector<hypermulator_hook_t::native_hook_type> native_hooks = { };

	for (address_type i = start_address; i < end_address;)
	{
		const auto current_physical_address = translate_virtual_address(i);

		if (!current_physical_address)
		{
			failed = true;

			break;
		}

		const size_type page_offset = i % page_size;
		const size_type size_left_page = page_size - page_offset;

		const size_type size_left_range = end_address - i;
		const size_type current_size = std::min(size_left_page, size_left_range);

		const address_type end_physical_address = *current_physical_address + current_size;

		const auto hook = callback(*current_physical_address, end_physical_address);

		if (!hook)
		{
			failed = true;

			break;
		}

		native_hooks.push_back(hook);

		i += current_size;
	}

	if (failed)
	{
		for (const auto& hook : native_hooks)
		{
			backend_->remove_hook(hook);
		}

		return { };
	}

	return native_hooks;
}

std::expected<emulator_t::hook_type, emulator_err_t> hypermulator_t::add_native_hook(
	const std::span<const hypermulator_hook_t::native_hook_type> native_hooks, const emulator_hook_t::callback_type& callback)
{
	if (native_hooks.empty())
	{
		return std::unexpected(emulator_err_t{ false });
	}

	for (const auto& native_hook : native_hooks)
	{
		if (!native_hook)
		{
			return std::unexpected(emulator_err_t{ false });
		}
	}

	return add_hook<hypermulator_hook_t>(backend_, native_hooks, callback);
}
