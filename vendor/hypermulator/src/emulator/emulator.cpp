#include "emulator.hpp"
#include "../guest/guest_virtual_processor.hpp"
#include "../guest/guest_vmexit.hpp"
#include "../arch/decoder.hpp"

#include <ia32.hpp>
#include <spdlog/spdlog.h>

template <class T, class Y>
static T align_up(T value, Y alignment)
{
	const Y remainder = value % alignment;
	const Y additional = remainder ? (alignment - remainder) : 0;

	return value + additional;
}

template <class T, class Y>
static T align_down(T value, Y alignment)
{
	return value & ~(alignment - 1);
}

static void reset_tf(hm::vcpu& cpu)
{
	rflags flags = cpu.reg_read<hm::reg::rflags, rflags>();

	if (!flags.trap_flag)
	{
		return;
	}

	flags.trap_flag = 0;

	cpu.reg_write<hm::reg::rflags>(flags.flags);
}

bool hm::emu_hook::in_range(const addr_t addr) const
{
	return start_addr <= addr && (!end_addr || addr < end_addr);
}

bool hm::emu_hook::in_aligned_range(const addr_t addr, const addr_t size) const
{
	const addr_t aligned_start = align_down(start_addr, emu::page_size);
	const addr_t aligned_end = align_up(end_addr, emu::page_size);

	return aligned_start <= addr + size && (!end_addr || addr - size < aligned_end);
}

hm::emu::emu(const machine_mode mode)
		:	partition_(std::make_shared<partition>(1)),
			mode_(mode)
{
	if (!partition_->set_up())
	{
		throw std::runtime_error("unable to set up partition");
	}

	if (!load_cpu_mode_default_state())
	{
		throw std::runtime_error("unable to load CPU mode default state");
	}

	reset_guest_exit_state();
}

bool hm::emu::run_at(const addr_t start_addr, const addr_t end_addr)
{
	if (mode_ == machine_mode_64 && reg_read<reg::cr3, std::uint64_t>() == 0 && !create_default_page_tables())
	{
		return false;
	}

	if ((mode_ == machine_mode_32 || mode_ == machine_mode_64) &&
		reg_read<reg::gdtr, table_reg>().base == 0 && !create_default_gdt())
	{
		return false;
	}

	set_pc(start_addr);

	if (!run())
	{
		return false;
	}

	if (end_addr && pc() != end_addr)
	{
		return false;
	}

	return true;
}

bool hm::emu::run()
{
	auto cpu = this->cpu();

	cpu.run();

	if (cpu.depth() != 0)
	{
		return true;
	}

	reset_tf(cpu);
	reset_step_cbs();

	return true;
}

void hm::emu::reset_step_cbs()
{
	if (single_step_cbs_.empty())
	{
		return;
	}

	single_step_cbs_.clear();
	block_hook_was_control_flow_ = false;

	for (std::size_t i = 0; i < hooks_.size(); i++)
	{
		const auto& hook = hooks_[i];

		if (hook->type == hook_type::code || hook->type == hook_type::basic_block)
		{
			prot_block_code_hook_mem_range(hook->start_addr, hook->end_addr, false);

			continue;
		}

		if (hook->type != hook_type::mem_access)
		{
			continue;
		}

		const auto& hook_mem = std::get<hook_mem_t>(hook->extra_data);
		const addr_t start_page = align_down(hook->start_addr, page_size);
		const addr_t end_page = align_up(hook->end_addr, page_size);

		for (addr_t page = start_page; page < end_page; page += page_size)
		{
			const auto prot = partition_->query_phys_mem_prot(page);

			if (prot && (*prot & hook_mem.prot))
			{
				partition_->prot_phys_mem(page, page_size, *prot & ~hook_mem.prot);
			}
		}
	}
}

void hm::emu::stop()
{
	auto cpu = this->cpu();

	cpu.stop();
}

void hm::emu::try_stop()
{
	auto cpu = this->cpu();

	cpu.try_stop();
}

bool hm::emu::configure_single_step()
{
	return partition_->set_debug_exception_exiting(true);
}

void hm::emu::reset_guest_exit_state()
{
	partition_->register_vmexit_cb(vmexit_reason::exception,
		[this](vcpu& cpu, vmexit_context& context)
		{
			return this->handle_exception(cpu, context);
		}
	);

	partition_->register_vmexit_cb(vmexit_reason::cpuid,
		[this](vcpu& cpu, vmexit_context& context)
		{
			return this->handle_cpuid_insn(cpu, context);
		}
	);

	partition_->register_vmexit_cb(vmexit_reason::rdtsc,
		[this](vcpu& cpu, vmexit_context& context)
		{
			return this->handle_rdtsc_insn(cpu, context);
		}
	);

	partition_->register_vmexit_cb(vmexit_reason::mem_access,
		[this](vcpu& cpu, vmexit_context& context)
		{
			return this->handle_mem_access(cpu, context);
		}
	);

	partition_->register_vmexit_cb(vmexit_reason::io_port_access,
		[this](vcpu& cpu, vmexit_context& context)
		{
			context.advance_rip(cpu);

			return true;
		}
	);

	partition_->set_cpuid_exiting(false);
	partition_->set_rdtsc_exiting(false);

	partition_->set_debug_exception_exiting(false);
	partition_->set_page_fault_exception_exiting(true);
}

bool hm::emu::map_phys_mem(const addr_t phys_addr, const std::size_t size,
                                         const mem_prot prot)
{
	return partition_->map_phys_mem(phys_addr, size, prot);
}

bool hm::emu::unmap_phys_mem(const addr_t phys_addr, const std::size_t size)
{
	return partition_->unmap_phys_mem(phys_addr, size);
}

bool hm::emu::prot_phys_mem(const addr_t phys_addr, const std::size_t size,
                                             const mem_prot prot)
{
	return partition_->prot_phys_mem(phys_addr, size, prot);
}

bool hm::emu::write_phys_mem(const addr_t phys_addr, const void* const buf,
                                           const std::size_t size)
{
	return partition_->write_phys_mem(phys_addr, buf, size);
}

bool hm::emu::write_phys_mem(const addr_t phys_addr,
                                           const std::span<const std::uint8_t> buf)
{
	return write_phys_mem(phys_addr, buf.data(), buf.size());
}

bool hm::emu::read_phys_mem(const addr_t phys_addr, void* const buf,
                                          const std::size_t size) const
{
	return partition_->read_phys_mem(phys_addr, buf, size);
}

bool hm::emu::read_phys_mem(const addr_t phys_addr,
                                          const std::span<std::uint8_t> buf) const
{
	return read_phys_mem(phys_addr, buf.data(), buf.size());
}

std::optional<hm::addr_t> hm::emu::virt_to_phys(const addr_t addr) const
{
	const auto cpu = this->cpu();

	return cpu.virt_to_phys(addr);
}

bool hm::emu::reg_write(const reg_t& r, const void* const value,
                                    const std::size_t size)
{
	auto cpu = this->cpu();

	return cpu.reg_write(r, value, size);
}

bool hm::emu::reg_read(const reg_t& r, void* const value,
                                   const std::size_t size) const
{
	const auto cpu = this->cpu();

	return cpu.reg_read(r, value, size);
}

hm::addr_t hm::emu::pc() const
{
	return reg_read<reg::rip, addr_t>();
}

void hm::emu::set_pc(const addr_t pc)
{
	return reg_write<reg::rip>(pc);
}

hm::vcpu hm::emu::cpu() const
{
	const auto cpus = partition_->cpus();

	if (cpus.empty())
	{
		throw std::logic_error("partition has no virtual processors");
	}

	return cpus[0];
}
