#include "exception_directory.hpp"

bool portable_executable::unwind_info_t::has_exception_handler() const noexcept
{
	return flags & 1;
}

bool portable_executable::unwind_info_t::has_unwind_handler() const noexcept
{
	return flags & 2;
}

bool portable_executable::unwind_info_t::has_chained_function() const noexcept
{
	return flags & 4;
}

std::optional<std::uint32_t> portable_executable::unwind_info_t::exception_handler_rva() const
{
	if (!has_exception_handler())
	{
		return { };
	}

	return *language_specific_data<std::uint32_t>();
}

std::optional<std::uint32_t> portable_executable::unwind_info_t::unwind_handler_rva() const
{
	if (!has_unwind_handler())
	{
		return { };
	}

	return *language_specific_data<std::uint32_t>();
}

std::optional<portable_executable::runtime_function_t> portable_executable::unwind_info_t::chained_function() const
{
	if (!has_chained_function())
	{
		return { };
	}

	return *language_specific_data<runtime_function_t>();
}

std::span<portable_executable::unwind_code_t> portable_executable::unwind_info_t::unwind_codes()
{
	return { codes, codes + unwind_code_count };
}

std::span<const portable_executable::unwind_code_t> portable_executable::unwind_info_t::unwind_codes() const
{
	return { codes, codes + unwind_code_count };
}

portable_executable::runtime_functions_iterator_t::value_type portable_executable::runtime_functions_iterator_t::operator*() const
{
	const auto function_begin = const_cast<std::uint8_t*>(m_module + m_current_function->begin_address);
	const auto function_end = const_cast<std::uint8_t*>(m_module + m_current_function->end_address);
	const auto unwind_info = reinterpret_cast<unwind_info_t*>(const_cast<std::uint8_t*>(m_module + m_current_function->unwind_info_rva));

	return value_type{ function_begin, function_end, unwind_info };
}

portable_executable::runtime_functions_iterator_t& portable_executable::runtime_functions_iterator_t::operator++()
{
	++m_current_function;

	return *this;
}

bool portable_executable::runtime_functions_iterator_t::operator==(const runtime_functions_iterator_t& other) const
{
	return m_current_function == other.m_current_function;
}

bool portable_executable::runtime_functions_iterator_t::operator!=(const runtime_functions_iterator_t& other) const
{
	return m_current_function != other.m_current_function;
}
