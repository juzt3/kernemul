#include "exception_dispatch.hpp"
#include "../kernel/exception_common.hpp"
#include "../kernel/kernel.hpp"
#include "../kernel/segments.hpp"
#include "../kernel/thread.hpp"

#include "../util/logs.hpp"

#include <cstring>
#include <vector>

// exception dispatch frame uses 0x4F0 for the CONTEXT region (larger than sizeof(CONTEXT) for alignment)
constexpr std::size_t ctx_size = 0x4F0;
static_assert(ctx_size >= sizeof(CONTEXT));

static thread_local bool dispatching_exception = false;

namespace
{
	struct dispatch_guard_t
	{
		dispatch_guard_t() noexcept
		{
			dispatching_exception = true;
		}

		~dispatch_guard_t()
		{
			dispatching_exception = false;
		}

		dispatch_guard_t(const dispatch_guard_t&) = delete;
		dispatch_guard_t& operator=(const dispatch_guard_t&) = delete;
	};
}

static void save_context(const std::shared_ptr<emulator_t>& emulator,
	std::uint8_t* ctx_buffer, const emulator_t::address_type faulting_rip)
{
	std::memset(ctx_buffer, 0, ctx_size);

	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_ALL;
	ctx.MxCsr = 0x1F80;

	ctx.SegCs = kernel::user_cs_selector;
	ctx.SegDs = kernel::user_ds_selector;
	ctx.SegEs = kernel::user_ds_selector;
	ctx.SegFs = kernel::user_ds_selector;
	ctx.SegGs = kernel::user_ds_selector;
	ctx.SegSs = kernel::user_ds_selector;

	ctx.FltSave.ControlWord = 0x27F;
	ctx.FltSave.StatusWord = 0;
	ctx.FltSave.TagWord = 0;
	ctx.FltSave.MxCsr = 0x1F80;
	ctx.FltSave.MxCsr_Mask = 0xFFFF;

	exception_common::read_gprs(emulator, ctx);
	exception_common::read_xmms(emulator, ctx);
	ctx.Rip = faulting_rip;

	for (std::size_t i = 0; i < 16; ++i)
	{
		std::memcpy(&ctx.VectorRegister[i], &ctx.FltSave.XmmRegisters[i], sizeof(xmm_state_register_t));
	}

	std::memcpy(ctx_buffer, &ctx, sizeof(ctx));
}

void user::dispatch_exception(const std::shared_ptr<emulator_t>& emulator,
	const std::uint32_t exception_code,
	const emulator_t::address_type exception_address,
	const std::uint64_t* parameters, const std::uint32_t parameter_count)
{
	const auto dispatcher_address = kernel::current_thread
		? kernel::current_thread->process()->ki_user_exception_dispatcher()
		: ki_user_exception_dispatcher_address;

	if (!dispatcher_address)
	{
		THREAD_ERR_LOG("dispatch_exception: KiUserExceptionDispatcher not resolved");
		return;
	}

	if (dispatching_exception)
	{
		THREAD_ERR_LOG("dispatch_exception: recursive exception dispatch blocked (code=0x{:08X}, addr=0x{:X})",
			exception_code, exception_address);
		return;
	}

	const dispatch_guard_t guard;

	const auto current_rsp = emulator->read_register<x86::reg::rsp, std::uint64_t>();
	const auto faulting_rip = emulator->read_register<x86::reg::rip, std::uint64_t>();

	// CONTEXT at RSP+0x000, EXCEPTION_RECORD at RSP+0x4F0, machine frame after
	// combined_size aligned to 0x10 so machine frame lands at 0x590
	const auto combined_size = (ctx_size + sizeof(EXCEPTION_RECORD) + 0xF) & ~static_cast<std::size_t>(0xF);
	const auto total_alloc = combined_size + exception_common::machine_frame_reserved;
	const auto new_sp = (current_rsp - total_alloc) & ~static_cast<std::uint64_t>(0xFF);

	// zero the entire region from new_sp to current_rsp
	const auto zero_size = current_rsp - new_sp;
	std::vector<std::uint8_t> frame(zero_size, 0);

	// CONTEXT64 at offset 0
	save_context(emulator, frame.data(), faulting_rip);

	// EXCEPTION_RECORD at offset ctx_size (0x4F0)
	EXCEPTION_RECORD er{};
	exception_common::build_exception_record(er, exception_code, exception_address, parameters, parameter_count);
	std::memcpy(frame.data() + ctx_size, &er, sizeof(er));

	// machine frame at offset combined_size (0x590)
	auto* mf = reinterpret_cast<exception_common::interrupt_frame_t*>(frame.data() + combined_size);
	mf->rip = faulting_rip;
	mf->cs = kernel::user_cs_selector;
	mf->rflags = emulator->read_register<x86::reg::rflags, std::uint64_t>();
	mf->rsp = current_rsp;
	mf->ss = kernel::user_ds_selector;

	static_cast<void>(emulator->write_virtual_memory(new_sp, frame.data(), zero_size));

	emulator->write_register<x86::reg::rsp>(new_sp);
	emulator->write_register<x86::reg::rip>(dispatcher_address);

	kernel::swap_to_usermode_segments(emulator);

	const auto gs_base = kernel::current_thread->state().gs_base;
	if (gs_base)
	{
		kernel::swap_to_usermode_gs(emulator, gs_base);
	}

	THREAD_LOG("dispatching exception 0x{:08X} to KiUserExceptionDispatcher (fault_rip=0x{:X}, rsp=0x{:X}->0x{:X})",
		exception_code, faulting_rip, current_rsp, new_sp);
}

void user::dispatch_access_violation(const std::shared_ptr<emulator_t>& emulator,
	const emulator_t::address_type fault_address, const bool is_write)
{
	const std::uint64_t params[] =
	{
		is_write ? 1ULL : 0ULL,
		fault_address,
	};

	const auto rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

	std::string sym_name = "unknown";
	if (const auto mod = kernel::find_module_from_rip(rip))
	{
		if (const auto sym = mod->find_symbol_by_address(rip))
		{
			sym_name = mod->name() + "!" + sym->first + "+0x" + std::format("{:X}", rip - sym->second);
		}
		else
		{
			sym_name = mod->name() + "+0x" + std::format("{:X}", rip - mod->base_address());
		}
	}

	const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
	const auto rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();
	const auto rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();

	emulator_t::address_type return_addr = 0;
	static_cast<void>(emulator->read_virtual_memory(rsp, &return_addr, sizeof(return_addr)));

	std::string caller_sym = "unknown";
	if (const auto caller_mod = kernel::find_module_from_rip(return_addr))
	{
		if (const auto caller_s = caller_mod->find_symbol_by_address(return_addr))
		{
			caller_sym = caller_mod->name() + "!" + caller_s->first + "+0x" + std::format("{:X}", return_addr - caller_s->second);
		}
		else
		{
			caller_sym = caller_mod->name() + "+0x" + std::format("{:X}", return_addr - caller_mod->base_address());
		}
	}

	THREAD_LOG("STATUS_ACCESS_VIOLATION at 0x{:X} [{}] ({} 0x{:X})",
		rip, sym_name, is_write ? "writing" : "reading", fault_address);
	THREAD_LOG("  caller=[RSP]=0x{:X} [{}], rcx=0x{:X}, rdx=0x{:X}",
		return_addr, caller_sym, rcx, rdx);

	// dump raw stack for call chain analysis
	for (int frame = 0; frame < 16; ++frame)
	{
		emulator_t::address_type val = 0;
		const auto stack_addr = rsp + static_cast<std::uint64_t>(frame) * 8;
		static_cast<void>(emulator->read_virtual_memory(stack_addr, &val, sizeof(val)));

		std::string frame_sym;
		if (const auto fmod = kernel::find_module_from_rip(val))
		{
			if (const auto fsym = fmod->find_symbol_by_address(val))
			{
				frame_sym = fmod->name() + "!" + fsym->first + "+0x" + std::format("{:X}", val - fsym->second);
			}
			else
			{
				frame_sym = fmod->name() + "+0x" + std::format("{:X}", val - fmod->base_address());
			}
		}
		THREAD_LOG("  [RSP+0x{:X}] = 0x{:X} {}", frame * 8, val, frame_sym);
	}

	dispatch_exception(emulator, exception_common::status_access_violation, rip, params, 2);
}

void user::clear_exception_dispatch_guard()
{
	dispatching_exception = false;
}
