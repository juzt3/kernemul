#pragma once
#include <Windows.h>
#include <WinHvPlatform.h>

#include <cstdint>

namespace hm
{
	struct segment_reg
	{
		std::uint64_t base;
		std::uint32_t limit;
		std::uint16_t selector;
		std::uint16_t attributes;
	};

	struct table_reg
	{
		std::uint16_t pad[3];
		std::uint16_t limit;
		std::uint64_t base;
	};

	struct reg_t
	{
		constexpr reg_t() = default;

		constexpr explicit reg_t(const WHV_REGISTER_NAME id_, const std::uint32_t size_)
				:	id(id_),
					size(size_) { }

		WHV_REGISTER_NAME id = WHvX64RegisterRax;
		std::uint32_t size = 0;
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

		constexpr reg_t gdtr(WHvX64RegisterGdtr, table_size);
		constexpr reg_t idtr(WHvX64RegisterIdtr, table_size);
		constexpr reg_t ldtr(WHvX64RegisterLdtr, table_size);
		constexpr reg_t tr(WHvX64RegisterTr, table_size);

		constexpr reg_t cs(WHvX64RegisterCs, segment_size);
		constexpr reg_t ss(WHvX64RegisterSs, segment_size);
		constexpr reg_t ds(WHvX64RegisterDs, segment_size);
		constexpr reg_t es(WHvX64RegisterEs, segment_size);
		constexpr reg_t fs(WHvX64RegisterFs, segment_size);
		constexpr reg_t gs(WHvX64RegisterGs, segment_size);

		constexpr reg_t pending_debug_exception(WHvX64RegisterPendingDebugException, pending_debug_exception_size);
		constexpr reg_t pending_interruption(WHvRegisterPendingInterruption, pending_interruption_size);
		constexpr reg_t pending_event(WHvRegisterPendingEvent, pending_event_size);
		constexpr reg_t interrupt_state(WHvRegisterInterruptState, interrupt_state_size);

		constexpr reg_t efer(WHvX64RegisterEfer, 8);
		constexpr reg_t kernel_gs_base(WHvX64RegisterKernelGsBase, 8);

		constexpr reg_t star(WHvX64RegisterStar, 8);
		constexpr reg_t lstar(WHvX64RegisterLstar, 8);
		constexpr reg_t cstar(WHvX64RegisterCstar, 8);
		constexpr reg_t sfmask(WHvX64RegisterSfmask, 8);

		constexpr reg_t cr0(WHvX64RegisterCr0, 8);
		constexpr reg_t xcr0(WHvX64RegisterXCr0, 8);
		constexpr reg_t cr2(WHvX64RegisterCr2, 8);
		constexpr reg_t cr3(WHvX64RegisterCr3, 8);
		constexpr reg_t cr4(WHvX64RegisterCr4, 8);
		constexpr reg_t cr8(WHvX64RegisterCr8, 8);

		constexpr reg_t dr0(WHvX64RegisterDr0, 8);
		constexpr reg_t dr1(WHvX64RegisterDr1, 8);
		constexpr reg_t dr2(WHvX64RegisterDr2, 8);
		constexpr reg_t dr3(WHvX64RegisterDr3, 8);
		constexpr reg_t dr6(WHvX64RegisterDr6, 8);
		constexpr reg_t dr7(WHvX64RegisterDr7, 8);

		constexpr reg_t rflags(WHvX64RegisterRflags, 8);
		constexpr reg_t rip(WHvX64RegisterRip, 8);

		constexpr reg_t rax(WHvX64RegisterRax, 8);
		constexpr reg_t rcx(WHvX64RegisterRcx, 8);
		constexpr reg_t rdx(WHvX64RegisterRdx, 8);
		constexpr reg_t rbx(WHvX64RegisterRbx, 8);
		constexpr reg_t rsp(WHvX64RegisterRsp, 8);
		constexpr reg_t rbp(WHvX64RegisterRbp, 8);
		constexpr reg_t rsi(WHvX64RegisterRsi, 8);
		constexpr reg_t rdi(WHvX64RegisterRdi, 8);
		constexpr reg_t r8(WHvX64RegisterR8, 8);
		constexpr reg_t r9(WHvX64RegisterR9, 8);
		constexpr reg_t r10(WHvX64RegisterR10, 8);
		constexpr reg_t r11(WHvX64RegisterR11, 8);
		constexpr reg_t r12(WHvX64RegisterR12, 8);
		constexpr reg_t r13(WHvX64RegisterR13, 8);
		constexpr reg_t r14(WHvX64RegisterR14, 8);
		constexpr reg_t r15(WHvX64RegisterR15, 8);

		constexpr reg_t xmm0(WHvX64RegisterXmm0, xmm_size);
		constexpr reg_t xmm1(WHvX64RegisterXmm1, xmm_size);
		constexpr reg_t xmm2(WHvX64RegisterXmm2, xmm_size);
		constexpr reg_t xmm3(WHvX64RegisterXmm3, xmm_size);
		constexpr reg_t xmm4(WHvX64RegisterXmm4, xmm_size);
		constexpr reg_t xmm5(WHvX64RegisterXmm5, xmm_size);
		constexpr reg_t xmm6(WHvX64RegisterXmm6, xmm_size);
		constexpr reg_t xmm7(WHvX64RegisterXmm7, xmm_size);
		constexpr reg_t xmm8(WHvX64RegisterXmm8, xmm_size);
		constexpr reg_t xmm9(WHvX64RegisterXmm9, xmm_size);
		constexpr reg_t xmm10(WHvX64RegisterXmm10, xmm_size);
		constexpr reg_t xmm11(WHvX64RegisterXmm11, xmm_size);
		constexpr reg_t xmm12(WHvX64RegisterXmm12, xmm_size);
		constexpr reg_t xmm13(WHvX64RegisterXmm13, xmm_size);
		constexpr reg_t xmm14(WHvX64RegisterXmm14, xmm_size);
		constexpr reg_t xmm15(WHvX64RegisterXmm15, xmm_size);
	}
}
