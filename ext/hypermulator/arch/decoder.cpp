#include "decoder.hpp"
#include <array>

static std::optional<ZydisDecoder> make_decoder(const hm::machine_mode_t mode)
{
	ZydisMachineMode zydis_mode;
	ZydisStackWidth stack_width;

	switch (mode)
	{
	case hm::machine_mode_16:
		zydis_mode = ZYDIS_MACHINE_MODE_REAL_16;
		stack_width = ZYDIS_STACK_WIDTH_16;
		break;
	case hm::machine_mode_32:
		zydis_mode = ZYDIS_MACHINE_MODE_LEGACY_32;
		stack_width = ZYDIS_STACK_WIDTH_32;
		break;
	case hm::machine_mode_64:
		zydis_mode = ZYDIS_MACHINE_MODE_LONG_64;
		stack_width = ZYDIS_STACK_WIDTH_64;
		break;
	default:
		return { };
	}

	ZydisDecoder decoder;

	if (ZYAN_FAILED(ZydisDecoderInit(&decoder, zydis_mode, stack_width)))
	{
		return { };
	}

	return decoder;
}

std::optional<hm::decoded_instruction_t> hm::decode_instruction(const machine_mode_t mode, const std::span<const std::uint8_t> bytes)
{
	if (bytes.empty() || max_instruction_length < bytes.size())
	{
		return { };
	}

	const auto decoder = make_decoder(mode);

	if (!decoder)
	{
		return { };
	}

	ZydisDecoderContext context;
	ZydisDecodedInstruction decoded_instruction;

	if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(
		&decoder.value(), &context, bytes.data(),
		bytes.size(), &decoded_instruction))
		)
	{
		return { };
	}

	return decoded_instruction_t{ decoded_instruction };
}

std::optional<hm::decoded_instruction_t> hm::decode_instruction_full(const machine_mode_t mode, const std::span<const std::uint8_t> bytes)
{
	if (bytes.empty() || max_instruction_length < bytes.size())
	{
		return { };
	}

	const auto decoder = make_decoder(mode);

	if (!decoder)
	{
		return { };
	}

	ZydisDecodedInstruction decoded_instruction;

	std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> decoded_operands;

	if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder.value(), bytes.data(), bytes.size(), &decoded_instruction, decoded_operands.data())))
	{
		return std::nullopt;
	}

	std::span<decoded_operand_t> span_operands = { reinterpret_cast<decoded_operand_t*>(decoded_operands.data()), decoded_instruction.operand_count };

	return decoded_instruction_t{ decoded_instruction, span_operands };
}