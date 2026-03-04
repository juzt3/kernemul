#pragma once
#include <Windows.h>
#include <WinHvPlatform.h>

#include <cstdint>

namespace hm
{
	struct guest_segment_register_t
	{
		std::uint64_t base;
		std::uint32_t limit;
		std::uint16_t selector;
		std::uint16_t attributes;
	};

	struct guest_table_register_t
	{
		std::uint16_t pad[3];
		std::uint16_t limit;
		std::uint64_t base;
	};

	struct guest_register_t
	{
		using id_type = WHV_REGISTER_NAME;
		using size_type = std::uint32_t;

		constexpr guest_register_t() = default;

		constexpr explicit guest_register_t(const id_type id_, const size_type size_)
				:	id(id_),
					size(size_) { }

		id_type id = WHvX64RegisterRax;
		size_type size = 0;
	};

	namespace reg
	{
		constexpr static std::uint64_t table_size = 16;
		constexpr static std::uint64_t segment_size = 16;
		constexpr static std::uint64_t xmm_size = 16;
		constexpr static std::uint64_t pending_event_size = 16;
		constexpr static std::uint64_t pending_debug_exception_size = 8;
		constexpr static std::uint64_t pending_interruption_size = 8;
		constexpr static std::uint64_t interrupt_state_size = 8;

		constexpr guest_register_t gdtr(WHvX64RegisterGdtr, table_size);
		constexpr guest_register_t idtr(WHvX64RegisterIdtr, table_size);
		constexpr guest_register_t ldtr(WHvX64RegisterLdtr, table_size);
		constexpr guest_register_t tr(WHvX64RegisterTr, table_size);

		constexpr guest_register_t cs(WHvX64RegisterCs, segment_size);
		constexpr guest_register_t ss(WHvX64RegisterSs, segment_size);
		constexpr guest_register_t ds(WHvX64RegisterDs, segment_size);
		constexpr guest_register_t es(WHvX64RegisterEs, segment_size);
		constexpr guest_register_t fs(WHvX64RegisterFs, segment_size);
		constexpr guest_register_t gs(WHvX64RegisterGs, segment_size);

		constexpr guest_register_t pending_debug_exception(WHvX64RegisterPendingDebugException, pending_debug_exception_size);
		constexpr guest_register_t pending_interruption(WHvRegisterPendingInterruption, pending_interruption_size);
		constexpr guest_register_t pending_event(WHvRegisterPendingEvent, pending_event_size);
		constexpr guest_register_t interrupt_state(WHvRegisterInterruptState, interrupt_state_size);

		constexpr guest_register_t efer(WHvX64RegisterEfer, 8);
		constexpr guest_register_t kernel_gs_base(WHvX64RegisterKernelGsBase, 8);

		constexpr guest_register_t cr0(WHvX64RegisterCr0, 8);
		constexpr guest_register_t xcr0(WHvX64RegisterXCr0, 8);
		constexpr guest_register_t cr2(WHvX64RegisterCr2, 8);
		constexpr guest_register_t cr3(WHvX64RegisterCr3, 8);
		constexpr guest_register_t cr4(WHvX64RegisterCr4, 8);

		constexpr guest_register_t dr0(WHvX64RegisterDr0, 8);
		constexpr guest_register_t dr1(WHvX64RegisterDr1, 8);
		constexpr guest_register_t dr2(WHvX64RegisterDr2, 8);
		constexpr guest_register_t dr3(WHvX64RegisterDr3, 8);
		constexpr guest_register_t dr6(WHvX64RegisterDr6, 8);
		constexpr guest_register_t dr7(WHvX64RegisterDr7, 8);

		constexpr guest_register_t rflags(WHvX64RegisterRflags, 8);
		constexpr guest_register_t rip(WHvX64RegisterRip, 8);

		constexpr guest_register_t rax(WHvX64RegisterRax, 8);
		constexpr guest_register_t rcx(WHvX64RegisterRcx, 8);
		constexpr guest_register_t rdx(WHvX64RegisterRdx, 8);
		constexpr guest_register_t rbx(WHvX64RegisterRbx, 8);
		constexpr guest_register_t rsp(WHvX64RegisterRsp, 8);
		constexpr guest_register_t rbp(WHvX64RegisterRbp, 8);
		constexpr guest_register_t rsi(WHvX64RegisterRsi, 8);
		constexpr guest_register_t rdi(WHvX64RegisterRdi, 8);
		constexpr guest_register_t r8(WHvX64RegisterR8, 8);
		constexpr guest_register_t r9(WHvX64RegisterR9, 8);
		constexpr guest_register_t r10(WHvX64RegisterR10, 8);
		constexpr guest_register_t r11(WHvX64RegisterR11, 8);
		constexpr guest_register_t r12(WHvX64RegisterR12, 8);
		constexpr guest_register_t r13(WHvX64RegisterR13, 8);
		constexpr guest_register_t r14(WHvX64RegisterR14, 8);
		constexpr guest_register_t r15(WHvX64RegisterR15, 8);

		constexpr guest_register_t xmm0(WHvX64RegisterXmm0, xmm_size);
		constexpr guest_register_t xmm1(WHvX64RegisterXmm1, xmm_size);
		constexpr guest_register_t xmm2(WHvX64RegisterXmm2, xmm_size);
		constexpr guest_register_t xmm3(WHvX64RegisterXmm3, xmm_size);
		constexpr guest_register_t xmm4(WHvX64RegisterXmm4, xmm_size);
		constexpr guest_register_t xmm5(WHvX64RegisterXmm5, xmm_size);
		constexpr guest_register_t xmm6(WHvX64RegisterXmm6, xmm_size);
		constexpr guest_register_t xmm7(WHvX64RegisterXmm7, xmm_size);
		constexpr guest_register_t xmm8(WHvX64RegisterXmm8, xmm_size);
		constexpr guest_register_t xmm9(WHvX64RegisterXmm9, xmm_size);
		constexpr guest_register_t xmm10(WHvX64RegisterXmm10, xmm_size);
		constexpr guest_register_t xmm11(WHvX64RegisterXmm11, xmm_size);
		constexpr guest_register_t xmm12(WHvX64RegisterXmm12, xmm_size);
		constexpr guest_register_t xmm13(WHvX64RegisterXmm13, xmm_size);
		constexpr guest_register_t xmm14(WHvX64RegisterXmm14, xmm_size);
		constexpr guest_register_t xmm15(WHvX64RegisterXmm15, xmm_size);
	}
}
