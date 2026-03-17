#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace portable_executable
{
    struct runtime_function_t
    {
        std::uint32_t begin_address;
        std::uint32_t end_address;
        std::uint32_t unwind_info_rva;
    };

    enum class unwind_register_t : std::uint8_t
    {
        rax = 0,
        rcx,
        rdx,
        rbx,
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

    enum class unwind_opcode_t : std::uint8_t
    {
        push_non_volatile = 0,
        stack_allocate_large = 1,
        stack_allocate_small = 2,
        set_frame_register = 3,
        save_non_volatile = 4,
        save_non_volatile_far = 5,
        epilog = 6,
        save_xmm128 = 8,
        same_xmm128_far = 9,
        push_machine_frame = 10
    };

    class unwind_code_t
    {
    public:
        using opcode_type = unwind_opcode_t;
        using offset_type = std::uint8_t;
        using info_type = std::uint8_t;

        unwind_code_t() = default;

    	explicit unwind_code_t(const offset_type offset, const unwind_opcode_t opcode, const info_type info) noexcept
    			:   offset_(offset),
					opcode_(opcode),
					info_(info) { }

        [[nodiscard]] offset_type offset() const noexcept
    	{
            return offset_;
    	}

        [[nodiscard]] opcode_type opcode() const noexcept
        {
            return opcode_;
        }

        [[nodiscard]] info_type info() const noexcept
        {
            return info_;
        }

    protected:
        offset_type offset_;
        unwind_opcode_t opcode_ : 4;
        info_type info_ : 4;
    };

    struct unwind_info_t
    {
        std::uint8_t version : 3;
        std::uint8_t flags : 5;
        std::uint8_t size_of_prolog;
        std::uint8_t unwind_code_count;
        std::uint8_t frame_register : 4;
        std::uint8_t frame_offset : 4;
        unwind_code_t codes[1];

        [[nodiscard]] bool has_exception_handler() const noexcept;
        [[nodiscard]] bool has_unwind_handler() const noexcept;
        [[nodiscard]] bool has_chained_function() const noexcept;

        [[nodiscard]] std::optional<std::uint32_t> exception_handler_rva()  const;
        [[nodiscard]] std::optional<std::uint32_t> unwind_handler_rva() const;
        [[nodiscard]] std::optional<runtime_function_t> chained_function() const;

        [[nodiscard]] std::span<unwind_code_t> unwind_codes();
        [[nodiscard]] std::span<const unwind_code_t> unwind_codes() const;

        template <class T>
        [[nodiscard]] T* language_specific_data()
        {
            return reinterpret_cast<T*>(&codes[(unwind_code_count + 1) & ~1]);
        }

        template <class T>
        [[nodiscard]] const T* language_specific_data() const
        {
            return const_cast<unwind_info_t*>(this)->language_specific_data<T>();
        }
    };

    struct runtime_function_descriptor_t
    {
        std::uint8_t* function_begin;
        std::uint8_t* function_end;

        unwind_info_t* unwind_info;
    };

    class runtime_functions_iterator_t
    {
        const std::uint8_t* m_module = nullptr;
        const runtime_function_t* m_current_function = nullptr;

    public:
        runtime_functions_iterator_t() = default;

        runtime_functions_iterator_t(const std::uint8_t* const module, const runtime_function_t* runtime_function) :
            m_module(module),
			m_current_function(runtime_function)
        {

        }

        using iterator_category = std::forward_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using value_type = runtime_function_descriptor_t;
        using pointer = value_type*;
        using reference = value_type&;

        value_type operator*() const;

        runtime_functions_iterator_t& operator++();

        bool operator==(const runtime_functions_iterator_t& other) const;
        bool operator!=(const runtime_functions_iterator_t& other) const;
    };

    template <typename T>
    class runtime_functions_range_t
    {
    private:
        using pointer_type = std::conditional_t<std::is_const_v<T>, const std::uint8_t*, std::uint8_t*>;
        using runtime_function_type = std::conditional_t<std::is_const_v<T>, const runtime_function_t*, runtime_function_t*>;

        pointer_type m_module = nullptr;

        runtime_function_type m_runtime_functions = nullptr;
        runtime_function_type m_end_runtime_functions = nullptr;

    public:
        runtime_functions_range_t() = default;

        runtime_functions_range_t(const pointer_type module, const std::uint32_t exception_directory_rva, const std::uint32_t exception_directory_size) :
            m_module(module),
            m_runtime_functions(reinterpret_cast<runtime_function_type>(module + exception_directory_rva)),
            m_end_runtime_functions(reinterpret_cast<runtime_function_type>(module + exception_directory_rva + exception_directory_size))
        {

        }

        [[nodiscard]] T begin() const
        {
            return { m_module, m_runtime_functions };
        }

        [[nodiscard]] T end() const
        {
            return { m_module, m_end_runtime_functions };
        }
    };
}