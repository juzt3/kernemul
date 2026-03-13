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
	class guest_virtual_processor_t;

	enum class vmexit_reason_t : std::uint16_t
	{
		none = 0,
		memory_access = 1,
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

	enum class exception_id_t : std::uint8_t
	{
		debug_trap = 1,
		page_fault = 14
	};

	struct vmexit_processor_state_t
	{
		using address_type = std::uint64_t;

		vmexit_processor_state_t() = default;

		explicit vmexit_processor_state_t(const WHV_VP_EXIT_CONTEXT& whv_context);

		[[nodiscard]] std::optional<address_type> physical_rip(const guest_virtual_processor_t& processor) const;

		address_type rip = 0;
		std::uint8_t instruction_length : 4 = 0;
	};

	struct memory_vmexit_t
	{
		memory_vmexit_t() = default;

		explicit memory_vmexit_t(const WHV_MEMORY_ACCESS_CONTEXT& whv_context);

		enum class access : std::uint8_t
		{
			read,
			write,
			execute
		};

		access type = access::read;

		bool physical_address_unmapped = true;
		bool virtual_address_valid = false;

		std::uint64_t physical_address = 0;
		std::uint64_t virtual_address = 0;

		std::array<std::uint8_t, max_instruction_length> instruction_bytes = { };
	};

	struct cpuid_vmexit_t
	{
		cpuid_vmexit_t() = default;

		explicit cpuid_vmexit_t(const WHV_X64_CPUID_ACCESS_CONTEXT& whv_context);

		std::uint64_t result_rax;
		std::uint64_t result_rcx;
		std::uint64_t result_rdx;
		std::uint64_t result_rbx;
	};

	struct rdtsc_vmexit_t
	{
		rdtsc_vmexit_t() = default;

		explicit rdtsc_vmexit_t(const WHV_X64_RDTSC_CONTEXT& whv_context);

		bool is_rdtscp;

		std::uint64_t tsc;
		std::uint64_t tsc_aux;
		std::uint64_t virtual_offset;
		std::uint64_t reference_time;
	};

	struct exception_vmexit_t
	{
		using error_code_type = std::uint32_t;

		exception_vmexit_t() = default;

		explicit exception_vmexit_t(const WHV_VP_EXCEPTION_CONTEXT& whv_context);

		exception_id_t id = exception_id_t::debug_trap;
		std::optional<error_code_type> error_code;
		std::uint64_t exception_parameter;

		std::array<std::uint8_t, max_instruction_length> instruction_bytes = { };
	};

	struct vmexit_context_t
	{
		vmexit_context_t() = default;

		explicit vmexit_context_t(const WHV_RUN_VP_EXIT_CONTEXT& whv_context);

		void advance_rip(guest_virtual_processor_t& virtual_processor);

		vmexit_reason_t reason = vmexit_reason_t::none;
		vmexit_processor_state_t processor_state = { };

		union
		{
			memory_vmexit_t memory_access = { };
			cpuid_vmexit_t cpuid;
			rdtsc_vmexit_t rdtsc;
			exception_vmexit_t exception;
		};
	};

	struct vmexit_callback_t
	{
		using routine_type = std::function<bool(guest_virtual_processor_t&, vmexit_context_t&)>;

		vmexit_reason_t reason;

		// returns true = continue executing guest
		// returns false = stop executing guest
		routine_type routine;
	};
}
