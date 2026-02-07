#pragma once
#include <unicorn/unicorn.h>
#include <functional>
#include <expected>
#include <memory>
#include <string>
#include <span>

class emulator_reg_t
{
public:
	using value_type = std::int32_t;

	constexpr explicit emulator_reg_t(const value_type reg)
			:	reg_(reg) { }

	[[nodiscard]] constexpr value_type value() const
	{
		return reg_;
	}

protected:
	value_type reg_ = 0;
};

class emulator_instruction_t
{
public:
	using value_type = std::int32_t;

	constexpr explicit emulator_instruction_t(const value_type instruction)
			:	instruction_(instruction) { }

	[[nodiscard]] constexpr value_type value() const
	{
		return instruction_;
	}

protected:
	value_type instruction_ = 0;
};

class emulator_err_t
{
public:
	emulator_err_t(const uc_err code)
			: code_(code) { }

	[[nodiscard]] std::string to_string() const
	{
		return uc_strerror(code_);
	}

	explicit operator bool() const
	{
		return code_ != UC_ERR_OK;
	}

	void throw_if(std::string_view info) const;

protected:
	uc_err code_ = UC_ERR_OK;
};

class emulator_t
{
public:
	using address_type = std::uintptr_t;
	using size_type = std::size_t;
	using protection_type = std::int32_t;

	static constexpr address_type thread_return_address = 0xF0000;
	static constexpr size_type memory_mapping_alignment = 0x1000;

	emulator_t();
	~emulator_t();

	[[nodiscard]] emulator_err_t run_at(address_type start_address, address_type end_address = 0) const;

	[[nodiscard]] emulator_err_t map_memory(address_type address, size_type size, protection_type protection) const;
	[[nodiscard]] emulator_err_t unmap_memory(address_type address, size_type size) const;

	[[nodiscard]] emulator_err_t read_memory(address_type address, void* buffer, size_type size) const;

	[[nodiscard]] emulator_err_t write_memory(address_type address, const void* buffer, size_type size) const;
	[[nodiscard]] emulator_err_t write_memory(address_type address, std::span<const std::uint8_t> buffer) const;

	[[nodiscard]] emulator_err_t load_memory(address_type address, std::span<const std::uint8_t> buffer, protection_type protection) const;

	[[nodiscard]] emulator_err_t read_register(emulator_reg_t reg, void* value) const;
	[[nodiscard]] emulator_err_t write_register(emulator_reg_t reg, const void* value) const;

protected:
	static size_type align_memory_map_size(const size_type size)
	{
		const size_type excess = size % memory_mapping_alignment;

		return excess ? size + memory_mapping_alignment - excess : size;
	}

	uc_engine* engine_ = nullptr;
};

namespace x86
{
	namespace reg
	{
		constexpr emulator_reg_t rsp(UC_X86_REG_RSP);
	}
}
