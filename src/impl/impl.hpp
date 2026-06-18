#pragma once
#include "../image/mapped_image.hpp"
#include "../kernel/kernel.hpp"
#include "../kernel/kernel_string.hpp"
#include "../util/util.hpp"
#include "../util/logs.hpp"

#include <ia32-doc/ia32.hpp>
#include <functional>
#include <random>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>

void redirect_function(const kernel::function_implementation_t& function_impl,
	const image_t& mapped_image, std::string_view name);

void redirect_function(const std::function<void()>& function_impl,
	const image_t& mapped_image, std::string_view name);

void write_return_value(const std::shared_ptr<emulator_t>& emulator, std::uint64_t value);
void write_nt_status(const std::shared_ptr<emulator_t>& emulator, std::uint32_t code);
void write_nt_success(const std::shared_ptr<emulator_t>& emulator);

std::uint64_t read_guest_vararg(const emulator_t& emulator, emulator_t::address_type va_list_address,
	std::size_t& index);

void write_guest_wstring_buffer(emulator_t& emulator, emulator_t::address_type buffer_address,
	std::size_t buffer_count, std::wstring_view str);

std::wstring guest_vswprintf(const emulator_t& emulator, std::wstring_view format,
	emulator_t::address_type va_list_address);

std::string guest_vsprintf(const emulator_t& emulator, std::string_view format,
	emulator_t::address_type va_list_address);

template <typename T>
struct is_emulator_object : std::false_type {};

template <typename T>
struct is_emulator_object<emulator_object_t<T>> : std::true_type {};

template <typename T>
inline constexpr bool is_emulator_object_v = is_emulator_object<T>::value;

inline std::uint64_t read_raw_arg(const std::shared_ptr<emulator_t>& emulator, std::size_t index)
{
	switch (index)
	{
	case 0: return emulator->read_register<x86::reg::rcx, std::uint64_t>();
	case 1: return emulator->read_register<x86::reg::rdx, std::uint64_t>();
	case 2: return emulator->read_register<x86::reg::r8, std::uint64_t>();
	case 3: return emulator->read_register<x86::reg::r9, std::uint64_t>();
	default:
	{
		const auto rsp = emulator->read_register<x86::reg::rsp, std::uint64_t>();
		std::uint64_t value = 0;
		static_cast<void>(emulator->read_virtual_memory(
			rsp + 0x28 + (index - 4) * 8, &value, sizeof(value)));
		return value;
	}
	}
}

template <typename T>
	requires std::is_arithmetic_v<T> || std::is_enum_v<T>
T resolve_argument(const std::shared_ptr<emulator_t>& emulator, std::size_t& index)
{
	return static_cast<T>(read_raw_arg(emulator, index++));
}

template <typename T>
	requires is_emulator_object_v<T>
T resolve_argument(const std::shared_ptr<emulator_t>& emulator, std::size_t& index)
{
	const auto address = static_cast<emulator_t::address_type>(read_raw_arg(emulator, index++));
	return T::view_at(emulator, address);
}

template <typename T>
	requires std::is_same_v<T, std::wstring>
T resolve_argument(const std::shared_ptr<emulator_t>& emulator, std::size_t& index)
{
	const auto address = static_cast<emulator_t::address_type>(read_raw_arg(emulator, index++));
	return kernel::read_guest_wstring(*emulator, address);
}

template <typename T>
	requires std::is_same_v<T, std::string>
T resolve_argument(const std::shared_ptr<emulator_t>& emulator, std::size_t& index)
{
	const auto address = static_cast<emulator_t::address_type>(read_raw_arg(emulator, index++));
	return kernel::read_guest_string(*emulator, address);
}

template <typename Result, typename... Args>
void forward_redirect(
	const std::shared_ptr<emulator_t>& emulator,
	Result (*handler)(const std::shared_ptr<emulator_t>&, Args...))
{
	std::size_t index = 0;
	std::tuple<const std::shared_ptr<emulator_t>&, Args...> args{
		emulator,
		resolve_argument<std::remove_cv_t<std::remove_reference_t<Args>>>(emulator, index)...
	};

	if constexpr (std::is_void_v<Result>)
	{
		std::apply(handler, std::move(args));
	}
	else
	{
		const auto result = std::apply(handler, std::move(args));
		write_return_value(emulator, static_cast<std::uint64_t>(result));
	}
}

template <auto Handler>
void redirect_handler(const std::shared_ptr<emulator_t>& emulator,
	const image_t& mapped_image, std::string_view name)
{
	redirect_function(
		[emulator] { forward_redirect(emulator, Handler); },
		mapped_image,
		name
	);
}
