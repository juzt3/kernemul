#include "exception.hpp"
#include "exception_common.hpp"
#include "kernel.hpp"

#include <portable_executable/image.hpp>
#include "../util/logs.hpp"

static x86::register_t unwind_reg_to_emulator_reg(const portable_executable::unwind_register_t reg)
{
	using enum portable_executable::unwind_register_t;

	switch (reg)
	{
	case rax: return x86::reg::rax;
	case rcx: return x86::reg::rcx;
	case rdx: return x86::reg::rdx;
	case rbx: return x86::reg::rbx;
	case rsp: return x86::reg::rsp;
	case rbp: return x86::reg::rbp;
	case rsi: return x86::reg::rsi;
	case rdi: return x86::reg::rdi;
	case r8:  return x86::reg::r8;
	case r9:  return x86::reg::r9;
	case r10: return x86::reg::r10;
	case r11: return x86::reg::r11;
	case r12: return x86::reg::r12;
	case r13: return x86::reg::r13;
	case r14: return x86::reg::r14;
	case r15: return x86::reg::r15;
	}

	throw std::runtime_error("invalid unwind register");
}

static std::uint8_t get_slot_count(const portable_executable::unwind_code_t& code)
{
	switch (code.opcode())
	{
	case portable_executable::unwind_opcode_t::push_non_volatile:
	case portable_executable::unwind_opcode_t::stack_allocate_small:
	case portable_executable::unwind_opcode_t::set_frame_register:
	case portable_executable::unwind_opcode_t::push_machine_frame:
		return 1;
	case portable_executable::unwind_opcode_t::save_non_volatile:
	case portable_executable::unwind_opcode_t::save_xmm128:
	case portable_executable::unwind_opcode_t::epilog:
		return 2;
	case portable_executable::unwind_opcode_t::save_non_volatile_far:
	case portable_executable::unwind_opcode_t::same_xmm128_far:
		return 3;
	case portable_executable::unwind_opcode_t::stack_allocate_large:
		return (code.info() == 0) ? 2 : 3;
	default:
		return 1;
	}
}

// return establisher frame
static emulator_t::address_type process_unwind_codes(const std::shared_ptr<emulator_t>& emulator,
	const portable_executable::unwind_info_t& unwind_info,
	const std::uint8_t offset_in_prolog)
{
	auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

	// todo: check when frame pointer value should be restored
	// maybe it should be restored in the unwind code iteration instead of at the top here
	if (unwind_info.frame_register != 0)
	{
		const auto frame_reg = static_cast<portable_executable::unwind_register_t>(unwind_info.frame_register);
		const auto frame_offset = static_cast<std::uint64_t>(unwind_info.frame_offset) * 16;

		std::uint64_t frame_value = 0;

		const emulator_err_t error = emulator->read_register(unwind_reg_to_emulator_reg(frame_reg), &frame_value);
		error.throw_if("read frame register");

		rsp = frame_value - frame_offset;
	}

	const emulator_t::address_type establisher_frame = rsp;

	const auto codes = unwind_info.unwind_codes();
	const auto* raw = reinterpret_cast<const std::uint16_t*>(codes.data());
	const auto code_count = unwind_info.unwind_code_count;

	for (std::uint8_t i = 0; i < code_count; )
	{
		const auto& code = codes[i];
		const auto slots = get_slot_count(code);

		if (offset_in_prolog < code.offset())
		{
			i += slots;

			continue;
		}

		const auto reg = static_cast<portable_executable::unwind_register_t>(code.info());

		switch (code.opcode())
		{
		case portable_executable::unwind_opcode_t::push_non_volatile:
		{
			std::uint64_t value = 0;
			const emulator_err_t error = emulator->read_virtual_memory(rsp, &value, sizeof(value));
			error.throw_if("read pushed register");

			const emulator_err_t write_error = emulator->write_register(unwind_reg_to_emulator_reg(reg), &value);
			write_error.throw_if("restore pushed register");

			rsp += 8;

			break;
		}
		case portable_executable::unwind_opcode_t::stack_allocate_large:
		{
			std::uint64_t size;

			if (code.info() == 0)
			{
				size = static_cast<std::uint64_t>(raw[i + 1]) * 8;
			}
			else
			{
				size = static_cast<std::uint64_t>(raw[i + 1])
					| (static_cast<std::uint64_t>(raw[i + 2]) << 16);
			}

			rsp += size;
			break;
		}
		case portable_executable::unwind_opcode_t::stack_allocate_small:
		{
			const auto size = (static_cast<std::uint64_t>(code.info()) * 8) + 8;

			rsp += size;
			break;
		}
		case portable_executable::unwind_opcode_t::set_frame_register:
		{
			break;
		}
		case portable_executable::unwind_opcode_t::save_non_volatile:
		{
			const auto offset = static_cast<std::uint64_t>(raw[i + 1]) * 8;

			std::uint64_t value = 0;
			const emulator_err_t error = emulator->read_virtual_memory(rsp + offset, &value, sizeof(value));
			error.throw_if("read saved register");

			const emulator_err_t write_error = emulator->write_register(unwind_reg_to_emulator_reg(reg), &value);
			write_error.throw_if("restore saved register");

			break;
		}
		case portable_executable::unwind_opcode_t::save_non_volatile_far:
		{
			const auto offset = static_cast<std::uint64_t>(raw[i + 1])
				| (static_cast<std::uint64_t>(raw[i + 2]) << 16);

			std::uint64_t value = 0;
			const emulator_err_t error = emulator->read_virtual_memory(rsp + offset, &value, sizeof(value));
			error.throw_if("read saved register far");

			const emulator_err_t write_error = emulator->write_register(unwind_reg_to_emulator_reg(reg), &value);
			write_error.throw_if("restore saved register far");

			break;
		}
		case portable_executable::unwind_opcode_t::save_xmm128:
		{
			// todo: restore value

			break;
		}
		case portable_executable::unwind_opcode_t::same_xmm128_far:
		{
			// todo: restore value

			break;
		}
		case portable_executable::unwind_opcode_t::epilog:
		{
			break;
		}
		case portable_executable::unwind_opcode_t::push_machine_frame:
		{
			if (code.info())
			{
				rsp += 8;
			}

			std::uint64_t frame_rip = 0;
			emulator_err_t error = emulator->read_virtual_memory(rsp, &frame_rip, sizeof(frame_rip));
			error.throw_if("read machine frame rip");

			emulator->write_register<x86::reg::rip>(frame_rip);

			rsp += 24;

			std::uint64_t frame_rsp = 0;
			error = emulator->read_virtual_memory(rsp, &frame_rsp, sizeof(frame_rsp));
			error.throw_if("read machine frame rsp");

			rsp = frame_rsp;

			break;
		}
		default:
		{
			THREAD_ERR_LOG("unknown unwind opcode {}", static_cast<std::uint8_t>(code.opcode()));
			break;
		}
		}

		i += slots;
	}

	emulator_t::address_type return_addr = 0;
	static_cast<void>(emulator->read_virtual_memory(rsp, &return_addr, sizeof(return_addr)));

	emulator->write_register<x86::reg::rsp>(rsp);

	return establisher_frame;
}

static emulator_t::address_type unwind_function(const std::shared_ptr<emulator_t>& emulator,
	const std::uint8_t* const module_base,
	const portable_executable::unwind_info_t& unwind_info,
	const std::uint8_t offset_in_prolog)
{
	const emulator_t::address_type establisher_frame = process_unwind_codes(emulator, unwind_info, offset_in_prolog);

	if (const auto chained_function = unwind_info.chained_function())
	{
		const auto* chained_info = reinterpret_cast<const portable_executable::unwind_info_t*>(
			module_base + chained_function->unwind_info_rva);

		constexpr std::uint8_t past_prolog = 0xFF;
		unwind_function(emulator, module_base, *chained_info, past_prolog);
	}

	return establisher_frame;
}

static emulator_t::address_type read_return_address(const std::shared_ptr<emulator_t>& emulator)
{
	const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

	emulator_t::address_type return_address = 0;

	const emulator_err_t error = emulator->read_virtual_memory(rsp, &return_address, sizeof(return_address));

	return return_address;
}

struct unwind_result_t
{
	emulator_t::address_type return_address = 0;
	emulator_t::address_type handler_address = 0;
	emulator_t::address_type establisher_frame = 0;
	emulator_t::address_type image_base = 0;
	emulator_t::address_type function_entry_address = 0;
	emulator_t::address_type handler_data_address = 0;
};

static std::optional<unwind_result_t> unwind_rip_in_function(const std::shared_ptr<emulator_t>& emulator, const emulator_t::address_type rip)
{
	const auto faulting_module = kernel::find_module_from_rip(rip);

	if (!faulting_module)
	{
		return { };
	}

	const auto buffer = faulting_module->buffer();
	const auto image = reinterpret_cast<const portable_executable::image_t*>(buffer.data());
	const auto module_base = buffer.data();

	const std::uint32_t rva = static_cast<std::uint32_t>(rip - faulting_module->base_address());
	const auto local_rip = reinterpret_cast<const std::uint8_t*>(module_base + rva);

	for (const auto [function_begin, function_end, unwind_info] : image->runtime_functions())
	{
		if (local_rip < function_begin || local_rip >= function_end)
		{
			continue;
		}

		const auto function_begin_rva = static_cast<std::uint32_t>(function_begin - module_base);
		const auto offset_in_prolog = static_cast<std::uint8_t>(
			std::min(rva - function_begin_rva, static_cast<std::uint32_t>(unwind_info->size_of_prolog)));

		const auto establisher_frame = unwind_function(emulator, module_base, *unwind_info, offset_in_prolog);

		unwind_result_t result;
		result.return_address = read_return_address(emulator);
		result.establisher_frame = establisher_frame;
		result.image_base = faulting_module->base_address();

		if (unwind_info->has_exception_handler() || unwind_info->has_unwind_handler())
		{
			const auto* language_data = unwind_info->language_specific_data<std::uint32_t>();

			result.handler_address = faulting_module->base_address() + language_data[0];

			const auto handler_data_rva = static_cast<std::uint32_t>(
				reinterpret_cast<const std::uint8_t*>(&language_data[1]) - module_base);
			result.handler_data_address = faulting_module->base_address() + handler_data_rva;
		}

		const auto& exception_dir = image->nt_headers()->optional_header.data_directories.exception_directory;
		const auto* pdata_begin = reinterpret_cast<const portable_executable::runtime_function_t*>(
			module_base + exception_dir.virtual_address);

		for (const auto* entry = pdata_begin; entry->begin_address; ++entry)
		{
			if (entry->begin_address == function_begin_rva)
			{
				const auto entry_rva = static_cast<std::uint32_t>(
					reinterpret_cast<const std::uint8_t*>(entry) - module_base);
				result.function_entry_address = faulting_module->base_address() + entry_rva;
				break;
			}
		}

		return result;
	}

	THREAD_LOG("leaf function at rva 0x{:X}, no unwind info", rva);

	unwind_result_t leaf_result;
	leaf_result.return_address = read_return_address(emulator);
	leaf_result.establisher_frame = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();

	return leaf_result;
}

static EXCEPTION_RECORD build_exception_record(const emulator_t::address_type faulting_rip,
	const std::uint32_t code, const emulator_t::address_type faulting_address)
{
	EXCEPTION_RECORD record{};

	if (code == exception_common::status_access_violation)
	{
		const std::uint64_t params[] = { 0, faulting_address };
		exception_common::build_exception_record(record, code, faulting_rip, params, 2);
	}
	else
	{
		exception_common::build_exception_record(record, code, faulting_rip, nullptr, 0);
	}

	return record;
}

static CONTEXT build_context(const std::shared_ptr<emulator_t>& emulator)
{
	CONTEXT ctx{};
	ctx.ContextFlags = CONTEXT_FULL;

	exception_common::read_gprs(emulator, ctx);
	ctx.Rip = emulator->read_register<x86::reg::rip, std::uint64_t>();

	return ctx;
}

static DISPATCHER_CONTEXT build_dispatcher_context(const unwind_result_t& unwind,
	const emulator_t::address_type faulting_rip,
	const emulator_t::address_type context_address)
{
	DISPATCHER_CONTEXT dispatch = { };

	dispatch.ControlPc = faulting_rip;
	dispatch.ImageBase = unwind.image_base;
	dispatch.FunctionEntry = reinterpret_cast<PRUNTIME_FUNCTION>(unwind.function_entry_address);
	dispatch.EstablisherFrame = unwind.establisher_frame;
	dispatch.ContextRecord = reinterpret_cast<PCONTEXT>(context_address);
	dispatch.LanguageHandler = reinterpret_cast<PEXCEPTION_ROUTINE>(unwind.handler_address);
	dispatch.HandlerData = reinterpret_cast<PVOID>(unwind.handler_data_address);
	dispatch.ScopeIndex = 0;

	return dispatch;
}

static bool call_exception_handler(const std::shared_ptr<emulator_t>& emulator,
	const unwind_result_t& unwind,
	const emulator_t::address_type original_rip,
	const emulator_t::address_type control_pc,
	const std::uint32_t code,
	const emulator_t::address_type faulting_address)
{
	const auto handler_module = kernel::find_module_from_rip(control_pc);

	if (!handler_module)
	{
		return false;
	}

	const auto buf = handler_module->buffer();
	const auto module_base = buf.data();
	const auto image_base = handler_module->base_address();

	const auto handler_data_rva = static_cast<std::uint32_t>(unwind.handler_data_address - image_base);
	const auto* scope_table_ptr = reinterpret_cast<const std::uint32_t*>(module_base + handler_data_rva);
	const auto scope_count = scope_table_ptr[0];
	const auto* scopes = reinterpret_cast<const exception_common::scope_entry_t*>(&scope_table_ptr[1]);

	const auto control_pc_rva = static_cast<std::uint32_t>(control_pc - image_base);

	THREAD_LOG("    scope_count={}, control_pc_rva=0x{:X}", scope_count, control_pc_rva);

	for (std::uint32_t i = 0; i < scope_count; ++i)
	{
		const auto& scope = scopes[i];

		if (control_pc_rva < scope.begin_address || control_pc_rva >= scope.end_address)
		{
			if (i < 5)
			{
				THREAD_LOG("    scope[{}]: [0x{:X},0x{:X}) handler=0x{:X} target=0x{:X} - SKIP (pc not in range)",
					i, scope.begin_address, scope.end_address, scope.handler_address, scope.jump_target);
			}

			continue;
		}

		if (!scope.jump_target)
		{
			THREAD_LOG("    scope[{}]: [0x{:X},0x{:X}) handler=0x{:X} target=0 - __finally, skipping",
				i, scope.begin_address, scope.end_address, scope.handler_address);

			continue;
		}

		THREAD_LOG("  scope[{}]: begin=0x{:X}, end=0x{:X}, handler=0x{:X}, target=0x{:X}",
			i, scope.begin_address, scope.end_address, scope.handler_address, scope.jump_target);

		if (scope.handler_address == 1)
		{
			const auto target = image_base + scope.jump_target;

			THREAD_LOG("  EXCEPTION_EXECUTE_HANDLER, jumping to 0x{:X}", target);

			emulator->write_register<x86::reg::rip>(target);
			emulator->write_register<x86::reg::rsp>(unwind.establisher_frame);

			return true;
		}

		const auto filter_address = image_base + scope.handler_address;

		auto record = build_exception_record(original_rip, code, faulting_address);
		auto ctx = build_context(emulator);

		constexpr emulator_t::size_type filter_stack_size = 0x4000;
		constexpr std::size_t data_offset = 0x100;
		const bool is_usermode = kernel::current_thread && kernel::current_thread->state().is_usermode;
		const auto allocation = emulator->heap_allocate(filter_stack_size, prot_read_write, true, is_usermode);
		emulator_err_t error = allocation.error_or({});
		error.throw_if("allocate filter context");

		const auto alloc_base = *allocation;
		const auto record_address = alloc_base + data_offset;
		const auto context_address = record_address + sizeof(EXCEPTION_RECORD);
		const auto pointers_address = context_address + sizeof(CONTEXT);

		error = emulator->write_virtual_memory(record_address, &record, sizeof(record));
		error.throw_if("write exception record for filter");

		error = emulator->write_virtual_memory(context_address, &ctx, sizeof(ctx));
		error.throw_if("write context for filter");

		const std::uint64_t exception_pointers[2] = { record_address, context_address };
		error = emulator->write_virtual_memory(pointers_address, &exception_pointers, sizeof(exception_pointers));
		error.throw_if("write exception pointers for filter");

		const emulator_t::address_type filter_rsp = ((alloc_base + filter_stack_size) & ~0xFull) - 0x28;
		const emulator_t::address_type filter_sentinel = emulator_t::thread_return_address;
		error = emulator->write_virtual_memory(filter_rsp, &filter_sentinel, sizeof(filter_sentinel));
		error.throw_if("write return sentinel for filter");

		const auto saved_rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();
		const auto saved_rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();
		const auto saved_rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
		const auto saved_rip = emulator->read_register<x86::reg::rip, emulator_t::address_type>();

		emulator->write_register<x86::reg::rcx>(pointers_address);
		emulator->write_register<x86::reg::rdx>(unwind.establisher_frame);
		emulator->write_register<x86::reg::rsp>(filter_rsp);

		THREAD_LOG("  calling filter at 0x{:X}", filter_address);

		const auto run_result = emulator->run_at(filter_address, emulator_t::thread_return_address);
		static_cast<void>(run_result);

		const auto filter_result = emulator->read_register<x86::reg::rax, std::int32_t>();

		emulator->write_register<x86::reg::rcx>(saved_rcx);
		emulator->write_register<x86::reg::rdx>(saved_rdx);
		emulator->write_register<x86::reg::rsp>(saved_rsp);
		emulator->write_register<x86::reg::rip>(saved_rip);

		THREAD_LOG("  filter returned {}", filter_result);

		if (filter_result < 0)
		{
			emulator->write_register<x86::reg::rip>(original_rip);

			return true;
		}

		if (filter_result > 0)
		{
			const auto target = image_base + scope.jump_target;

			emulator->write_register<x86::reg::rip>(target);
			emulator->write_register<x86::reg::rsp>(unwind.establisher_frame);

			return true;
		}
	}

	return false;
}

bool kernel::handle_exception(const std::shared_ptr<emulator_t>& emulator, const emulator_t::address_type rip,
	const std::uint32_t code, const emulator_t::address_type faulting_address, const bool allow_no_handler)
{
	emulator_t::address_type current_rip = rip;

	THREAD_LOG("exception dispatch: code=0x{:X}, rip=0x{:X}, faulting_address=0x{:X}",
		code, rip, faulting_address);

	constexpr std::size_t max_frames = 64;

	for (std::size_t depth = 0; depth < max_frames; ++depth)
	{
		const auto unwind = unwind_rip_in_function(emulator, current_rip);

		if (!unwind)
		{
			THREAD_WARN_LOG("exception dispatch: rip 0x{:X} not in any module", current_rip);

			break;
		}

		const auto faulting_module = kernel::find_module_from_rip(current_rip);
		const auto frame_rva = faulting_module
			? static_cast<std::uint32_t>(current_rip - faulting_module->base_address())
			: 0u;

		THREAD_LOG("  frame[{}]: rip=0x{:X} (rva=0x{:X}), handler=0x{:X}, ret=0x{:X}",
			depth, current_rip, frame_rva,
			unwind->handler_address, unwind->return_address);

		if (unwind->handler_address)
		{
			if (call_exception_handler(emulator, *unwind, rip, current_rip, code, faulting_address))
			{
				THREAD_LOG("exception handled at frame {}, continuing at 0x{:X}",
					depth, emulator->read_register<x86::reg::rip, emulator_t::address_type>());

				return true;
			}
		}

		const auto rsp = emulator->read_register<x86::reg::rsp, emulator_t::address_type>();
		emulator->write_register<x86::reg::rsp>(rsp + 8);

		current_rip = unwind->return_address;
	}

	THREAD_ERR_LOG("exception dispatch: unhandled exception code=0x{:X} at 0x{:X}", code, rip);

	if (!allow_no_handler)
	{
		emulator->stop();
	}

	return false;
}
