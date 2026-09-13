#pragma once
#include "instruction.hpp"
#include <Zydis/Zydis.h>

namespace hm
{
	class decoder_reg
	{
	public:
		using native_t = ZydisRegister;

		constexpr decoder_reg() noexcept = default;

		explicit constexpr decoder_reg(const native_t value) noexcept
				:	value_(value) { }

		[[nodiscard]] bool in_same_family(const decoder_reg& other) const noexcept
		{
			constexpr auto mode = ZYDIS_MACHINE_MODE_LONG_64;

			const auto enclosing = ZydisRegisterGetLargestEnclosing(mode, value_);
			const auto other_enclosing = ZydisRegisterGetLargestEnclosing(mode, other.value_);

			return enclosing == other_enclosing;
		}

		[[nodiscard]] constexpr operator bool() const noexcept
		{
			return value_ != ZYDIS_REGISTER_NONE;
		}

		[[nodiscard]] bool operator==(const decoder_reg& other) const noexcept
		{
			return value_ == other.value_ || in_same_family(other);
		}

		[[nodiscard]] bool operator!=(const decoder_reg& other) const noexcept
		{
			return value_ != other.value_ && !in_same_family(other);
		}

		[[nodiscard]] constexpr operator ZydisRegister() const noexcept
		{
			return value_;
		}

		static const decoder_reg none;
		static const decoder_reg rip;
		static const decoder_reg rflags;
		static const decoder_reg rax;
		static const decoder_reg rcx;
		static const decoder_reg rdx;
		static const decoder_reg rbx;
		static const decoder_reg rsi;
		static const decoder_reg rdi;
		static const decoder_reg rbp;
		static const decoder_reg rsp;
		static const decoder_reg r8;
		static const decoder_reg r9;
		static const decoder_reg r10;
		static const decoder_reg r11;
		static const decoder_reg r12;
		static const decoder_reg r13;
		static const decoder_reg r14;
		static const decoder_reg r15;

	protected:
		native_t value_ = ZYDIS_REGISTER_NONE;
	};
}
