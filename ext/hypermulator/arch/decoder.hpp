#pragma once
#include "instruction.hpp"
#include "register.hpp"
#include <optional>
#include <span>
#include <vector>

namespace hm
{
	class decoded_operand_t
	{
	public:
		enum class op_type : std::uint8_t
		{
			none,
			reg,
			imm,
			mem,
			ptr
		};

		struct imm_type
		{
			union
			{
				std::uint64_t u;
				std::int64_t s;
			} value;

			bool is_relative;
			bool is_signed;
		};

		struct mem_type
		{
			decoder_register base;
			decoder_register index;
			decoder_register segment;

			std::optional<std::int64_t> displacement = std::nullopt;
			std::uint8_t scale;
		};

		using reg_type = decoder_register;

		constexpr decoded_operand_t() noexcept = default;

		constexpr explicit decoded_operand_t(const ZydisDecodedOperand& value) noexcept
				:	value_(value) { }

		[[nodiscard]] op_type type() const noexcept
		{
			switch (value_.type)
			{
			case ZYDIS_OPERAND_TYPE_REGISTER:
				return op_type::reg;
			case ZYDIS_OPERAND_TYPE_MEMORY:
				return op_type::mem;
			case ZYDIS_OPERAND_TYPE_POINTER:
				return op_type::ptr;
			case ZYDIS_OPERAND_TYPE_IMMEDIATE:
				return op_type::imm;
			default:
				return op_type::none;
			}
		}

		[[nodiscard]] std::optional<reg_type> reg() const noexcept
		{
			if (type() != op_type::reg)
			{
				return std::nullopt;
			}

			return reg_type{ value_.reg.value };
		}

		void set_reg(const reg_type reg) noexcept
		{
			value_.reg.value = reg;

			set_type(op_type::reg);
		}

		[[nodiscard]] std::optional<imm_type> imm() const noexcept
		{
			if (type() != op_type::imm)
			{
				return std::nullopt;
			}

			imm_type imm;

			imm.value.u = value_.imm.value.u;
			imm.is_relative = value_.imm.is_relative;
			imm.is_signed = value_.imm.is_signed;

			return imm;
		}

		void set_imm(const imm_type imm) noexcept
		{
			value_.imm.value.u = imm.value.u;
			value_.imm.is_relative = imm.is_relative;
			value_.imm.is_signed = imm.is_signed;

			set_type(op_type::imm);
		}

		[[nodiscard]] std::optional<mem_type> mem() const noexcept
		{
			if (type() != op_type::mem)
			{
				return std::nullopt;
			}

			mem_type mem;

			if (value_.mem.disp.has_displacement)
			{
				mem.displacement = value_.mem.disp.value;
			}

			mem.scale = value_.mem.scale;

			mem.base = reg_type(value_.mem.base);
			mem.index = reg_type(value_.mem.index);
			mem.segment = reg_type(value_.mem.segment);

			return mem;
		}

		void set_mem(const mem_type& mem) noexcept
		{
			value_.mem.segment = mem.segment;
			value_.mem.base = mem.base;
			value_.mem.index = mem.index;
			value_.mem.scale = mem.scale;

			if (mem.displacement.has_value())
			{
				value_.mem.disp.value = *mem.displacement;
				value_.mem.disp.has_displacement = true;
			}
			else
			{
				value_.mem.disp.has_displacement = false;
			}

			set_type(op_type::mem);
		}

		explicit operator ZydisDecodedOperand&() noexcept
		{
			return value_;
		}

		explicit operator const ZydisDecodedOperand&() const noexcept
		{
			return value_;
		}

	protected:
		void set_type(const op_type type) noexcept
		{
			switch (type)
			{
			case op_type::reg:
				value_.type = ZYDIS_OPERAND_TYPE_REGISTER;
			case op_type::mem:
				value_.type = ZYDIS_OPERAND_TYPE_MEMORY;
			case op_type::ptr:
				value_.type = ZYDIS_OPERAND_TYPE_POINTER;
			case op_type::imm:
				value_.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			default:
				value_.type = ZYDIS_OPERAND_TYPE_UNUSED;
			}
		}

		ZydisDecodedOperand value_;
	};

	class decoded_instruction_t
	{
	public:
		decoded_instruction_t() = default;

		explicit decoded_instruction_t(const ZydisDecodedInstruction& value, const std::span<decoded_operand_t> operands = { })
				:	value_(value),
					operands_(operands.begin(), operands.end()) { }

		[[nodiscard]] bool is_jump() const noexcept
		{
			return value_.meta.category == ZYDIS_CATEGORY_COND_BR ||
				value_.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
		}

		[[nodiscard]] bool is_call() const noexcept
		{
			return value_.meta.category == ZYDIS_CATEGORY_CALL;
		}

		[[nodiscard]] bool is_ret() const noexcept
		{
			return value_.meta.category == ZYDIS_CATEGORY_RET;
		}

		[[nodiscard]] bool is_interrupt() const noexcept
		{
			return value_.meta.category == ZYDIS_CATEGORY_INTERRUPT;
		}

		[[nodiscard]] bool is_syscall() const noexcept
		{
			return value_.meta.category == ZYDIS_CATEGORY_SYSCALL;
		}

		[[nodiscard]] std::span<decoded_operand_t> operands() noexcept
		{
			return operands_;
		}

		[[nodiscard]] std::span<const decoded_operand_t> operands() const noexcept
		{
			return operands_;
		}

		[[nodiscard]] std::span<decoded_operand_t> visible_operands() noexcept
		{
			return { operands_.begin(), value_.operand_count_visible };
		}

		[[nodiscard]] std::span<const decoded_operand_t> visible_operands() const noexcept
		{
			return { operands_.begin(), value_.operand_count_visible };
		}

	protected:
		ZydisDecodedInstruction value_ = { };
		std::vector<decoded_operand_t> operands_;
	};

	std::optional<decoded_instruction_t> decode_instruction(machine_mode_t mode, std::span<const std::uint8_t> bytes);
	std::optional<decoded_instruction_t> decode_instruction_full(machine_mode_t mode, std::span<const std::uint8_t> bytes);
}
