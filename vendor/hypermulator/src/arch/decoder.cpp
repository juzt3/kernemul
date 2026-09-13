#include "decoder.hpp"
#include <array>

static std::optional<ZydisDecoder> make_decoder(const hm::machine_mode mode)
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

std::optional<hm::decoded_insn> hm::decode_insn(const machine_mode mode, const std::span<const std::uint8_t> bytes)
{
	if (bytes.empty() || max_insn_len < bytes.size())
	{
		return { };
	}

	const auto decoder = make_decoder(mode);

	if (!decoder)
	{
		return { };
	}

	ZydisDecoderContext context;
	ZydisDecodedInstruction raw_insn;

	if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(
		&decoder.value(), &context, bytes.data(),
		bytes.size(), &raw_insn))
		)
	{
		return { };
	}

	return decoded_insn{ raw_insn };
}

std::optional<hm::decoded_insn> hm::decode_insn_full(const machine_mode mode, const std::span<const std::uint8_t> bytes)
{
	if (bytes.empty() || max_insn_len < bytes.size())
	{
		return { };
	}

	const auto decoder = make_decoder(mode);

	if (!decoder)
	{
		return { };
	}

	ZydisDecodedInstruction raw_insn;

	std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> raw_operands;

	if (ZYAN_FAILED(ZydisDecoderDecodeFull(&decoder.value(), bytes.data(), bytes.size(), &raw_insn, raw_operands.data())))
	{
		return std::nullopt;
	}

	std::span<decoded_operand> span_operands = { reinterpret_cast<decoded_operand*>(raw_operands.data()), raw_insn.operand_count };

	return decoded_insn{ raw_insn, span_operands };
}
