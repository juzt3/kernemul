#pragma once
#include "instruction.hpp"
#include <Zydis/Zydis.h>

namespace hm
{
	class decoder_register
	{
	public:
		using native_type = ZydisRegister;
		using size_type = std::uint16_t;

		constexpr decoder_register() noexcept = default;

		explicit constexpr decoder_register(const native_type value) noexcept
				:	value_(value) { }

		[[nodiscard]] bool in_same_family(const decoder_register& other) const noexcept
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

		[[nodiscard]] bool operator==(const decoder_register& other) const noexcept
		{
			return value_ == other.value_ || in_same_family(other);
		}

		[[nodiscard]] bool operator!=(const decoder_register& other) const noexcept
		{
			return value_ != other.value_ && !in_same_family(other);
		}

		[[nodiscard]] constexpr operator ZydisRegister() const noexcept
		{
			return value_;
		}

		static const decoder_register none;
		static const decoder_register rip;
		static const decoder_register rflags;
		static const decoder_register rax;
		static const decoder_register rcx;
		static const decoder_register rdx;
		static const decoder_register rbx;
		static const decoder_register rsi;
		static const decoder_register rdi;
		static const decoder_register rbp;
		static const decoder_register rsp;
		static const decoder_register r8;
		static const decoder_register r9;
		static const decoder_register r10;
		static const decoder_register r11;
		static const decoder_register r12;
		static const decoder_register r13;
		static const decoder_register r14;
		static const decoder_register r15;

	protected:
		native_type value_ = ZYDIS_REGISTER_NONE;
	};
}
