#pragma once
#include "instruction.hpp"

#include <Zydis/Zydis.h>
#include <optional>
#include <span>

namespace hm
{
	class decoded_instruction_t
	{
	public:
		decoded_instruction_t() = default;

		explicit decoded_instruction_t(const ZydisDecodedInstruction& value)
				:	value_(value) { }

		[[nodiscard]] bool is_jump() const
		{
			return value_.meta.category == ZYDIS_CATEGORY_COND_BR ||
				value_.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
		}

		[[nodiscard]] bool is_call() const
		{
			return value_.meta.category == ZYDIS_CATEGORY_CALL;
		}

		[[nodiscard]] bool is_ret() const
		{
			return value_.meta.category == ZYDIS_CATEGORY_RET;
		}

		[[nodiscard]] bool is_interrupt() const
		{
			return value_.meta.category == ZYDIS_CATEGORY_INTERRUPT;
		}

		[[nodiscard]] bool is_syscall() const
		{
			return value_.meta.category == ZYDIS_CATEGORY_SYSCALL;
		}

	protected:
		ZydisDecodedInstruction value_ = { };
	};

	std::optional<decoded_instruction_t> decode_instruction(machine_mode_t mode, std::span<const std::uint8_t> bytes);
}
