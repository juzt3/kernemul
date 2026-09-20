#pragma once
#include <Windows.h>
#include <WinHvPlatform.h>
#include <functional>
#include <optional>
#include <array>

#include "guest_virtual_processor.hpp"
#include "../arch/instruction.hpp"

namespace hm
{
	class vcpu;

	enum class vmexit_reason : std::uint16_t
	{
		none = 0,
		mem_access = 1,
		io_port_access = 2,
		unrecoverable_exception = 4,
		invalid_processor_register_value = 5,
		unsupported_feature = 6,
		interrupt_window = 7,
		halt = 8,
		apic_eoi = 9,
		synic_sint_deliverable = 0xA,

		msr_access = 0x1000,
		cpuid = 0x1001,
		exception = 0x1002,
		rdtsc = 0x1003,
		apic_smi_trap = 0x1004,
		hypercall = 0x1005,
		apic_init_sipi_trap = 0x1006,
		apic_write_trap = 0x1007,

		cancelled = 0x2001
	};

	enum class exception_id : std::uint8_t
	{
		divide_error = 0,
		debug_trap = 1,
		breakpoint = 3,
		invalid_opcode = 6,
		general_protection = 13,
		page_fault = 14
	};

	enum exception_mask : std::uint64_t
	{
		excp_none = 0,
		excp_divide_error = 1ull << static_cast<std::uint8_t>(exception_id::divide_error),
		excp_debug_trap = 1ull << static_cast<std::uint8_t>(exception_id::debug_trap),
		excp_breakpoint = 1ull << static_cast<std::uint8_t>(exception_id::breakpoint),
		excp_invalid_opcode = 1ull << static_cast<std::uint8_t>(exception_id::invalid_opcode),
		excp_general_protection = 1ull << static_cast<std::uint8_t>(exception_id::general_protection),
		excp_page_fault = 1ull << static_cast<std::uint8_t>(exception_id::page_fault),

		excp_all = excp_divide_error | excp_debug_trap | excp_breakpoint |
			excp_invalid_opcode | excp_general_protection | excp_page_fault
	};

	constexpr exception_mask operator|(exception_mask a, exception_mask b) { return static_cast<exception_mask>(static_cast<std::uint64_t>(a) | static_cast<std::uint64_t>(b)); }
	constexpr exception_mask operator&(exception_mask a, exception_mask b) { return static_cast<exception_mask>(static_cast<std::uint64_t>(a) & static_cast<std::uint64_t>(b)); }
	constexpr exception_mask operator~(exception_mask a) { return static_cast<exception_mask>(~static_cast<std::uint64_t>(a) & excp_all); }
	constexpr exception_mask& operator|=(exception_mask& a, exception_mask b) { return a = a | b; }
	constexpr exception_mask& operator&=(exception_mask& a, exception_mask b) { return a = a & b; }

	constexpr exception_mask to_exception_mask(const exception_id id)
	{
		return static_cast<exception_mask>(1ull << static_cast<std::uint8_t>(id));
	}

	struct vmexit_cpu_state
	{

		vmexit_cpu_state() = default;

		explicit vmexit_cpu_state(const WHV_VP_EXIT_CONTEXT& whv_context);

		[[nodiscard]] std::optional<addr_t> phys_rip(const vcpu& cpu) const;

		addr_t rip = 0;
		std::uint8_t insn_len : 4 = 0;
	};

	struct mem_vmexit
	{
		mem_vmexit() = default;

		explicit mem_vmexit(const WHV_MEMORY_ACCESS_CONTEXT& whv_context);

		enum class access : std::uint8_t
		{
			read,
			write,
			execute
		};

		access type = access::read;

		bool phys_addr_unmapped = true;
		bool virt_addr_valid = false;

		std::uint64_t phys_addr = 0;
		std::uint64_t virt_addr = 0;

		std::array<std::uint8_t, max_insn_len> insn_bytes = { };
	};

	struct cpuid_vmexit
	{
		cpuid_vmexit() = default;

		explicit cpuid_vmexit(const WHV_X64_CPUID_ACCESS_CONTEXT& whv_context);

		std::uint64_t result_rax;
		std::uint64_t result_rcx;
		std::uint64_t result_rdx;
		std::uint64_t result_rbx;
	};

	struct rdtsc_vmexit
	{
		rdtsc_vmexit() = default;

		explicit rdtsc_vmexit(const WHV_X64_RDTSC_CONTEXT& whv_context);

		bool is_rdtscp;

		std::uint64_t tsc;
		std::uint64_t tsc_aux;
		std::uint64_t virt_offset;
		std::uint64_t reference_time;
	};

	struct exception_vmexit
	{

		exception_vmexit() = default;

		explicit exception_vmexit(const WHV_VP_EXCEPTION_CONTEXT& whv_context);

		exception_id id = exception_id::debug_trap;
		std::optional<std::uint32_t> error_code;
		std::uint64_t exception_parameter;

		std::array<std::uint8_t, max_insn_len> insn_bytes = { };
	};

	struct vmexit_context
	{
		vmexit_context() = default;

		explicit vmexit_context(const WHV_RUN_VP_EXIT_CONTEXT& whv_context);

		void advance_rip(vcpu& cpu);

		vmexit_reason reason = vmexit_reason::none;
		vmexit_cpu_state cpu_state = { };

		union
		{
			mem_vmexit mem_access = { };
			cpuid_vmexit cpuid;
			rdtsc_vmexit rdtsc;
			exception_vmexit exception;
		};
	};

	struct vmexit_callback
	{
		using routine_t = std::function<bool(vcpu&, vmexit_context&)>;

		vmexit_reason reason;

		// returns true = continue executing guest
		// returns false = stop executing guest
		routine_t cb;
	};
}
