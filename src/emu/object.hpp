#pragma once
#include "defs.hpp"
#include "addr_space.hpp"

template <class T>
class emu_object
{
public:
	emu_object() noexcept = default;

	emu_object(addr_space& mem, const addr_t addr) noexcept
		:	mem_(&mem), addr_(addr) { }

	[[nodiscard]] T read(const std::size_t index = 0) const
	{
		return mem_->read_mem<T>(addr_ + index * sizeof(T));
	}

	void write(const T& val, const std::size_t index = 0)
	{
		mem_->write_mem<T>(addr_ + index * sizeof(T), val);
	}

	[[nodiscard]] addr_t address() const noexcept { return addr_; }
	[[nodiscard]] addr_space* mem() const noexcept { return mem_; }
	explicit operator bool() const noexcept { return addr_ != 0; }

protected:
	addr_space* mem_ = nullptr;
	addr_t addr_ = 0;
};
