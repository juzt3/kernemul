#pragma once
#include <unicorn/unicorn.h>

#include <functional>
#include <expected>
#include <format>
#include <variant>
#include <memory>
#include <string>
#include <span>
#include <stdexcept>

namespace x86
{
	struct register_t
	{
	public:
		using size_type = std::uint32_t;

		enum class id_type : std::uint8_t
		{
			cr0,
			cr2,
			cr3,
			cr4,

			rip,
			rflags,

			rax,
			rcx,
			rbx,
			rdx,
			rsp,
			rbp,
			rsi,
			rdi,
			r8,
			r9,
			r10,
			r11,
			r12,
			r13,
			r14,
			r15
		};

		static constexpr size_type bit_64_size = 8;

		constexpr explicit register_t(const id_type id_, const size_type size_)
				:	id(id_),
					size(size_) { }


		id_type id = { };
		size_type size = { };
	};

	namespace reg
	{
#define DEF_REG(name, size) constexpr static register_t name{ register_t::id_type::name, size };
#define DEF_REG_64(name) DEF_REG(name, register_t::bit_64_size)

		DEF_REG_64(cr0);
		DEF_REG_64(cr2);
		DEF_REG_64(cr3);
		DEF_REG_64(cr4);

		DEF_REG_64(rip);
		DEF_REG_64(rflags);

		DEF_REG_64(rax);
		DEF_REG_64(rcx);
		DEF_REG_64(rbx);
		DEF_REG_64(rdx);
		DEF_REG_64(rsp);
		DEF_REG_64(rbp);
		DEF_REG_64(rsi);
		DEF_REG_64(rdi);
		DEF_REG_64(r8);
		DEF_REG_64(r9);
		DEF_REG_64(r10);
		DEF_REG_64(r11);
		DEF_REG_64(r12);
		DEF_REG_64(r13);
		DEF_REG_64(r14);
		DEF_REG_64(r15);
	}

	enum class msr : std::uint32_t
	{
		efer = 0xC0000080
	};

	enum class insn : std::uint8_t
	{
		cpuid,
		rdtsc
	};
}

enum protection_t : std::uint8_t
{
	prot_none = 0,
	prot_read = 1,
	prot_write = 2,
	prot_read_write = 3,
	prot_execute = 4,
	prot_read_execute = 5,
	prot_write_execute = 6,
	prot_all = 7
};

class emulator_t;

class emulator_hook_t
{
public:
	using address_type = std::uint64_t;
	using protection_type = protection_t;

	using invalid_memory_callback = std::function<bool(address_type faulting_address, protection_t access)>;  // returns true = has handled invalid access properly (e.g. mapping address in)
	using memory_access_callback = std::function<void(address_type faulting_address, protection_t access)>;
	using code_callback = std::function<void()>;
	using instruction_callback = std::function<bool()>; // returns true = instruction should be skipped

	using callback_type = std::variant<invalid_memory_callback, memory_access_callback, code_callback, instruction_callback>;

	explicit emulator_hook_t(callback_type callback)
			:	callback_(std::move(callback)) { }

	[[nodiscard]] const callback_type& callback() const
	{
		return callback_;
	}

protected:
	callback_type callback_ = { };
};

class emulator_err_t
{
public:
	emulator_err_t() = default;

	explicit emulator_err_t(const bool status)
			:	message_(status ? "" : "failed") { }

	explicit emulator_err_t(const uc_err code)
			:	message_(code == UC_ERR_OK ? "" : uc_strerror(code)) { }

	[[nodiscard]] std::string to_string() const
	{
		return message_;
	}

	explicit operator bool() const
	{
		return !message_.empty();
	}

	void throw_if(std::string_view info) const
	{
		if (*this)
		{
			throw std::runtime_error(std::format("{}: '{}'", info, to_string()));
		}
	}

protected:
	std::string message_;
};

class emulator_t : public std::enable_shared_from_this<emulator_t>
{
public:
	using address_type = std::uintptr_t;
	using size_type = std::size_t;
	using protection_type = std::int32_t;
	using hook_type = std::shared_ptr<emulator_hook_t>;

	static constexpr address_type default_start_address = 0;
	static constexpr address_type default_end_address = std::numeric_limits<address_type>::max();

	static constexpr address_type heap_base = 0x3F0000;
	static constexpr address_type thread_return_address = 0xF0000;
	static constexpr size_type memory_mapping_alignment = 0x1000;

	[[nodiscard]] virtual emulator_err_t run_at(address_type start_address, address_type end_address = 0) = 0;

	[[nodiscard]] virtual emulator_err_t map_memory(address_type address, size_type size, protection_type protection) = 0;
	[[nodiscard]] virtual emulator_err_t unmap_memory(address_type address, size_type size) = 0;

	[[nodiscard]] virtual emulator_err_t read_memory(address_type address, void* buffer, size_type size) const = 0;

	[[nodiscard]] emulator_err_t read_memory(const address_type address, const std::span<std::uint8_t> buffer) const
	{
		return read_memory(address, buffer.data(), buffer.size());
	}

	[[nodiscard]] virtual emulator_err_t write_memory(address_type address, const void* buffer, size_type size) = 0;

	[[nodiscard]] emulator_err_t write_memory(const address_type address, const std::span<const std::uint8_t> buffer)
	{
		return write_memory(address, buffer.data(), buffer.size());
	}

	[[nodiscard]] emulator_err_t load_memory(const address_type address, const std::span<const std::uint8_t> buffer,
	                                         const protection_type protection)
	{
		emulator_err_t error = map_memory(address, buffer.size(), protection);

		if (error)
		{
			return error;
		}

		error = write_memory(address, buffer);

		if (error)
		{
			(void)unmap_memory(address, buffer.size());
		}

		return error;
	}

	[[nodiscard]] virtual emulator_err_t read_register(x86::register_t reg, void* value) const = 0;
	[[nodiscard]] virtual emulator_err_t write_register(x86::register_t reg, const void* value) = 0;

	template <x86::register_t Register, class T>
	T read_register()
	{
		static_assert(std::is_trivially_copyable_v<T>, "reading non trivially copyable type from a register");

		T value = { };

		emulator_err_t error;

		if constexpr (sizeof(T) == Register.size)
		{
			error = read_register(Register, &value);
		}
		else
		{
			std::array<std::uint8_t, Register.size> buffer = { };

			error = read_register(Register, buffer.data());

			const size_type copy_size = std::min(sizeof(T), static_cast<std::size_t>(Register.size));

			std::memcpy(&value, buffer.data(), copy_size);
		}

		error.throw_if("read register");

		return value;
	}

	template <x86::register_t Register, class T>
	void write_register(const T& value)
	{
		static_assert(std::is_trivially_copyable_v<T>, "writing non trivially copyable type to a register");
		static_assert(sizeof(T) <= Register.size, "writing too large of a value to a register");

		emulator_err_t error;

		if constexpr (sizeof(T) == Register.size)
		{
			error = write_register(Register, &value);
		}
		else
		{
			std::array<std::uint8_t, Register.size> buffer = { };

			std::memcpy(buffer.data(), &value, sizeof(T));

			error = write_register(Register, buffer.data());
		}

		error.throw_if("write register");
	}

	virtual std::expected<hook_type, emulator_err_t> hook_instruction(
		x86::insn instruction, const emulator_hook_t::instruction_callback& callback, address_type start_address,
		address_type end_address) = 0;

	virtual std::expected<hook_type, emulator_err_t> hook_basic_block(
		const emulator_hook_t::code_callback& callback, address_type start_address, address_type end_address) = 0;

	virtual std::expected<hook_type, emulator_err_t> hook_code(
		const emulator_hook_t::code_callback& callback,address_type start_address, address_type end_address) = 0;

	virtual std::expected<hook_type, emulator_err_t> hook_invalid_memory(
		const emulator_hook_t::invalid_memory_callback& callback, protection_type monitored_protection,
		address_type start_address, address_type end_address) = 0;

	virtual std::expected<hook_type, emulator_err_t> hook_memory(
		const emulator_hook_t::memory_access_callback& callback, protection_type monitored_protection,
		address_type start_address, address_type end_address) = 0;

protected:
	template <class HookT, class ...Args>
	std::shared_ptr<HookT> add_hook(Args&&... arguments)
	{
		const auto hook = std::make_shared<HookT>(std::forward<Args>(arguments)...);

		hooks_.push_back(hook);

		return hook;
	}

	void push_hook(std::shared_ptr<emulator_hook_t> hook)
	{
		hooks_.push_back(std::move(hook));
	}

	template <class T, class Y>
	static constexpr T align_up(T value, Y alignment)
	{
		const Y remainder = value % alignment;
		const Y additional = remainder ? (alignment - remainder) : 0;

		return value + additional;
	}

	template <class T, class Y>
	static constexpr T align_down(T value, Y alignment)
	{
		return value & ~(alignment - 1);
	}

	std::vector<hook_type> hooks_;
};
