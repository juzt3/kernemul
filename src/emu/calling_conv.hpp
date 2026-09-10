#pragma once
#include "emu.hpp"
#include <functional>
#include <tuple>
#include <type_traits>
#include <utility>

struct calling_conv
{
	virtual ~calling_conv() = default;

	template <typename T>
	T arg(vcpu& cpu, std::size_t index) const
	{
		T v{};
		arg_read(cpu, index, &v, sizeof(v));
		return v;
	}

	template <typename T>
	void ret(vcpu& cpu, const T& val) const
	{
		ret_write(cpu, &val, sizeof(val));
	}

protected:
	virtual void arg_read(vcpu& cpu, std::size_t index, void* buf, std::size_t size) const = 0;
	virtual void ret_write(vcpu& cpu, const void* buf, std::size_t size) const = 0;
};

struct x86_win_conv : calling_conv
{
protected:
	void arg_read(vcpu& cpu, std::size_t index, void* buf, std::size_t size) const override
	{
		static constexpr reg_t regs[] = { x86::rcx, x86::rdx, x86::r8, x86::r9 };

		if (index < 4)
			cpu.reg_read(regs[index], buf, size);
		else
			cpu.read_virt_mem(cpu.reg(x86::rsp) + 0x08 * (index + 1), buf, size);
	}

	void ret_write(vcpu& cpu, const void* buf, std::size_t size) const override
	{
		cpu.reg_write(x86::rax, buf, size);
	}
};

template <typename T>
struct function_traits;

template <typename R, typename... Args>
struct function_traits<R(*)(Args...)>
{
	using return_type = R;
	using args = std::tuple<Args...>;
	static constexpr std::size_t arity = sizeof...(Args);
};

template <typename C, typename R, typename... Args>
struct function_traits<R(C::*)(Args...) const>
{
	using return_type = R;
	using args = std::tuple<Args...>;
	static constexpr std::size_t arity = sizeof...(Args);
};

template <typename C, typename R, typename... Args>
struct function_traits<R(C::*)(Args...)>
{
	using return_type = R;
	using args = std::tuple<Args...>;
	static constexpr std::size_t arity = sizeof...(Args);
};

template <typename C, typename R, typename... Args>
struct function_traits<R(C::*)(Args...) const noexcept>
{
	using return_type = R;
	using args = std::tuple<Args...>;
	static constexpr std::size_t arity = sizeof...(Args);
};

template <typename C, typename R, typename... Args>
struct function_traits<R(C::*)(Args...) noexcept>
{
	using return_type = R;
	using args = std::tuple<Args...>;
	static constexpr std::size_t arity = sizeof...(Args);
};

template <typename T>
struct function_traits : function_traits<decltype(&T::operator())> {};

namespace detail
{

template <typename ArgsTuple>
constexpr bool first_is_vcpu()
{
	if constexpr (std::tuple_size_v<ArgsTuple> == 0)
		return false;
	else
		return std::is_same_v<std::remove_cvref_t<std::tuple_element_t<0, ArgsTuple>>, vcpu>
			&& std::is_lvalue_reference_v<std::tuple_element_t<0, ArgsTuple>>;
}

template <typename ArgsTuple, bool HasVcpu, typename F, std::size_t... I>
void call_with_conv(vcpu& cpu, const calling_conv& conv, F& fn, std::index_sequence<I...>)
{
	using traits = function_traits<std::decay_t<F>>;
	using R = typename traits::return_type;

	constexpr std::size_t offset = HasVcpu ? 1 : 0;

	if constexpr (HasVcpu)
	{
		if constexpr (std::is_void_v<R>)
			fn(cpu, conv.arg<std::tuple_element_t<I + offset, ArgsTuple>>(cpu, I)...);
		else
			conv.ret(cpu, fn(cpu, conv.arg<std::tuple_element_t<I + offset, ArgsTuple>>(cpu, I)...));
	}
	else
	{
		if constexpr (std::is_void_v<R>)
			fn(conv.arg<std::tuple_element_t<I, ArgsTuple>>(cpu, I)...);
		else
			conv.ret(cpu, fn(conv.arg<std::tuple_element_t<I, ArgsTuple>>(cpu, I)...));
	}
}

}

template <typename F>
std::function<void(vcpu&)> make_redirect(std::shared_ptr<const calling_conv> conv, F&& fn)
{
	using traits = function_traits<std::decay_t<F>>;
	using args_tuple = typename traits::args;
	constexpr auto arity = traits::arity;
	constexpr bool has_vcpu = detail::first_is_vcpu<args_tuple>();
	constexpr auto conv_arity = has_vcpu ? arity - 1 : arity;

	return [c = std::move(conv), f = std::forward<F>(fn)](vcpu& cpu) mutable
	{
		detail::call_with_conv<args_tuple, has_vcpu>(
			cpu, *c, f, std::make_index_sequence<conv_arity>{});
	};
}
