#pragma once

#include "../emulator/emulator.hpp"
#include "thread.hpp"

#include <Windows.h>

#include <cstdint>
#include <cstring>
#include <memory>

namespace exception_common
{
	struct interrupt_frame_t
	{
		std::uint64_t rip;
		std::uint64_t cs;
		std::uint64_t rflags;
		std::uint64_t rsp;
		std::uint64_t ss;
	};

	constexpr std::size_t machine_frame_reserved = 0x40;

	constexpr std::uint32_t status_access_violation = 0xC0000005;
	constexpr std::uint32_t status_guard_page_violation = 0x80000001;
	constexpr std::uint32_t status_integer_divide_by_zero = 0xC0000094;
	constexpr std::uint32_t status_single_step = 0x80000004;
	constexpr std::uint32_t status_breakpoint = 0x80000003;
	constexpr std::uint32_t status_array_bounds_exceeded = 0xC000008C;
	constexpr std::uint32_t status_illegal_instruction = 0xC000001D;

	struct scope_entry_t
	{
		std::uint32_t begin_address;
		std::uint32_t end_address;
		std::uint32_t handler_address;
		std::uint32_t jump_target;
	};

	inline void read_gprs(const std::shared_ptr<emulator_t>& emulator, CONTEXT& ctx)
	{
		ctx.Rax = emulator->read_register<x86::reg::rax, std::uint64_t>();
		ctx.Rcx = emulator->read_register<x86::reg::rcx, std::uint64_t>();
		ctx.Rdx = emulator->read_register<x86::reg::rdx, std::uint64_t>();
		ctx.Rbx = emulator->read_register<x86::reg::rbx, std::uint64_t>();
		ctx.Rsp = emulator->read_register<x86::reg::rsp, std::uint64_t>();
		ctx.Rbp = emulator->read_register<x86::reg::rbp, std::uint64_t>();
		ctx.Rsi = emulator->read_register<x86::reg::rsi, std::uint64_t>();
		ctx.Rdi = emulator->read_register<x86::reg::rdi, std::uint64_t>();
		ctx.R8 = emulator->read_register<x86::reg::r8, std::uint64_t>();
		ctx.R9 = emulator->read_register<x86::reg::r9, std::uint64_t>();
		ctx.R10 = emulator->read_register<x86::reg::r10, std::uint64_t>();
		ctx.R11 = emulator->read_register<x86::reg::r11, std::uint64_t>();
		ctx.R12 = emulator->read_register<x86::reg::r12, std::uint64_t>();
		ctx.R13 = emulator->read_register<x86::reg::r13, std::uint64_t>();
		ctx.R14 = emulator->read_register<x86::reg::r14, std::uint64_t>();
		ctx.R15 = emulator->read_register<x86::reg::r15, std::uint64_t>();
		ctx.EFlags = emulator->read_register<x86::reg::rflags, std::uint32_t>();
	}

	inline void read_xmms(const std::shared_ptr<emulator_t>& emulator, CONTEXT& ctx)
	{
		const xmm_state_register_t xmms[16] =
		{
			emulator->read_register<x86::reg::xmm0, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm1, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm2, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm3, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm4, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm5, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm6, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm7, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm8, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm9, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm10, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm11, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm12, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm13, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm14, xmm_state_register_t>(),
			emulator->read_register<x86::reg::xmm15, xmm_state_register_t>(),
		};

		for (std::size_t i = 0; i < 16; ++i)
		{
			std::memcpy(&ctx.FltSave.XmmRegisters[i], &xmms[i], sizeof(xmm_state_register_t));
		}
	}

	inline void build_exception_record(EXCEPTION_RECORD& record,
		const std::uint32_t code, const emulator_t::address_type exception_address,
		const std::uint64_t* parameters, const std::uint32_t parameter_count)
	{
		record = {};
		record.ExceptionCode = code;
		record.ExceptionAddress = reinterpret_cast<PVOID>(exception_address);
		record.NumberParameters = parameter_count;

		for (std::uint32_t i = 0; i < parameter_count && i < EXCEPTION_MAXIMUM_PARAMETERS; ++i)
		{
			record.ExceptionInformation[i] = parameters[i];
		}
	}

	inline std::uint32_t vector_to_exception_code(const std::uint32_t vector)
	{
		switch (vector)
		{
		case 0:  return status_integer_divide_by_zero;
		case 1:  return status_single_step;
		case 3:  return status_breakpoint;
		case 5:  return status_array_bounds_exceeded;
		case 6:  return status_illegal_instruction;
		case 13: return status_access_violation;
		case 14: return status_access_violation;
		case 17: return status_access_violation;
		default: return 0;
		}
	}
}
