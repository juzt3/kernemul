#pragma once
#include "defs.hpp"
#include "addr_space.hpp"
#include "mmu.hpp"
#include "emu.hpp"
#include "../util/log.hpp"
#include <typeinfo>
#include <string>

template <class T>
class emu_object
{
public:
	emu_object() noexcept = default;

	emu_object(addr_space& space_, const addr_t addr, bool monitored = false) noexcept
		:	space_(&space_), addr_(addr)
	{
		if (monitored)
			monitor();
	}

	emu_object(addr_space& space_, const addr_t addr, std::string name, bool monitored = false) noexcept
		:	space_(&space_), addr_(addr), name_(std::move(name))
	{
		if (monitored)
			monitor();
	}

	[[nodiscard]] T read(const std::size_t index = 0) const
	{
		return space_->read_mem<T>(addr_ + index * sizeof(T));
	}

	void write(const T& val, const std::size_t index = 0)
	{
		space_->write_mem<T>(addr_ + index * sizeof(T), val);
	}

	emu_hook* monitor()
	{
		const auto base = addr_;
		const auto name = name_;

		hook_ = space_->mmu_->emu()->hook_mem(addr_, addr_ + sizeof(T) - 1, prot_rw,
			[base, name](vcpu& cpu, addr_t accessed, std::size_t, mem_prot access)
			{
				const auto rip = cpu.pc();
				const auto offset = accessed - base;

				LOG_INFO("0x{:X} accessed ({} '{}')+0x{:X} (type={})",
					rip, typeid(T).name(), name, offset, static_cast<unsigned>(access));
			});

		return hook_;
	}

	void unmonitor()
	{
		if (hook_)
		{
			space_->mmu_->emu()->remove_hook(hook_);
			hook_ = nullptr;
		}
	}

	static emu_object allocate(addr_space& space, std::string name = {}, bool monitored = false)
	{
		const auto addr = space.alloc(sizeof(T), prot_rw);
		return emu_object(space, addr, std::move(name), monitored);
	}

	static emu_object allocate_at(addr_space& space, addr_t addr, std::string name = {}, bool monitored = false)
	{
		space.mmu_->map_virt(space, addr, sizeof(T), prot_rw);
		return emu_object(space, addr, std::move(name), monitored);
	}

	void set_name(std::string name) { name_ = std::move(name); }

	[[nodiscard]] bool monitored() const noexcept { return hook_ != nullptr; }
	[[nodiscard]] const std::string& name() const noexcept { return name_; }
	[[nodiscard]] addr_t address() const noexcept { return addr_; }
	[[nodiscard]] addr_space* space() const noexcept { return space_; }
	explicit operator bool() const noexcept { return addr_ != 0; }

protected:
	addr_space* space_ = nullptr;
	addr_t addr_ = 0;
	emu_hook* hook_ = nullptr;
	std::string name_;
};

template <>
class emu_object<void>
{
public:
	emu_object() noexcept = default;

	emu_object(addr_space& space, const addr_t addr, bool = false) noexcept
		:	space_(&space), addr_(addr) {}

	[[nodiscard]] addr_t address() const noexcept { return addr_; }
	[[nodiscard]] addr_space* space() const noexcept { return space_; }
	explicit operator bool() const noexcept { return addr_ != 0; }

private:
	addr_space* space_ = nullptr;
	addr_t addr_ = 0;
};
