#pragma once
#include "defs.hpp"
#include "addr_space.hpp"

template <class T>
class emu_object
{
public:
	emu_object() noexcept = default;

	emu_object(addr_space& space_, const addr_t addr) noexcept
		:	space_(&space_), addr_(addr) { }

	[[nodiscard]] T read(const std::size_t index = 0) const
	{
		return space_->read_mem<T>(addr_ + index * sizeof(T));
	}

	void write(const T& val, const std::size_t index = 0)
	{
		space_->write_mem<T>(addr_ + index * sizeof(T), val);
	}

	[[nodiscard]] addr_t address() const noexcept { return addr_; }
	[[nodiscard]] addr_space* space() const noexcept { return space_; }
	explicit operator bool() const noexcept { return addr_ != 0; }

protected:
	addr_space* space_ = nullptr;
	addr_t addr_ = 0;
};
