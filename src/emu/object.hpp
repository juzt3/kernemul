#pragma once
#include "defs.hpp"
#include "addr_space.hpp"
#include "mmu.hpp"
#include "emu.hpp"
#include "../util/log.hpp"
#include "../sym/symbol.hpp"
#include <format>
#include <cstddef>
#include <type_traits>
#include <typeinfo>
#include <string>

template <class C, class M>
[[nodiscard]] std::size_t member_offset(M C::* const member) noexcept
{
	return reinterpret_cast<std::size_t>(
		&(static_cast<C*>(nullptr)->*member));
}

template <class T>
class emu_object
{
public:
	using value_type = T;

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

	// A copy is a second view of the same bytes, not a second watcher of them: the hook belongs
	// to whoever installed it, and duplicating the raw pointer would let either copy remove a
	// hook the other still names.
	emu_object(const emu_object& other)
		:	space_(other.space_), addr_(other.addr_), name_(other.name_) { }

	emu_object& operator=(const emu_object& other)
	{
		if (this != &other)
		{
			space_ = other.space_;
			addr_ = other.addr_;
			name_ = other.name_;
			hook_ = nullptr;
		}

		return *this;
	}

	// A move does carry it, so `obj = emu_object<T>(space, va, "name", true)` keeps watching.
	emu_object(emu_object&& other) noexcept
		:	space_(other.space_), addr_(other.addr_), hook_(other.hook_),
			name_(std::move(other.name_))
	{
		other.hook_ = nullptr;
	}

	emu_object& operator=(emu_object&& other) noexcept
	{
		if (this != &other)
		{
			space_ = other.space_;
			addr_ = other.addr_;
			hook_ = other.hook_;
			name_ = std::move(other.name_);
			other.hook_ = nullptr;
		}

		return *this;
	}

	[[nodiscard]] T read(const std::size_t index = 0) const
	{
		return space_->read_mem<T>(addr_ + index * sizeof(T));
	}

	void write(const T& val, const std::size_t index = 0)
	{
		space_->write_mem<T>(addr_ + index * sizeof(T), val);
	}

	template <class C, class M>
		requires std::is_same_v<C, T> || std::is_base_of_v<C, T>
	[[nodiscard]] emu_object<std::remove_extent_t<M>> field(M C::* const member) const
	{
		return emu_object<std::remove_extent_t<M>>(*space_, addr_ + member_offset(member));
	}

	template <class M>
	[[nodiscard]] emu_object<M> field_at(const std::size_t offset) const
	{
		return emu_object<M>(*space_, addr_ + offset);
	}

	emu_hook* monitor()
	{
		// Installing twice would leak the first hook and log every access a second time.
		if (hook_ || !space_ || !addr_)
			return hook_;

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

// Guest memory an access is worth reporting, named so the log says what was touched rather than
// only where. The range is watched as one hook: a per-element hook would multiply the cost of a
// table by its length for no extra information.
inline emu_hook* monitor_range(addr_space& space, const addr_t addr, const std::size_t size,
	std::string name)
{
	if (!addr || !size)
		return nullptr;

	// A range the guest cannot reach is not an error here -- a module mapped into another
	// address space translates only while that space is current -- so it is reported and skipped
	// rather than thrown out of whatever was mapping it.
	try
	{
		return space.mmu_->emu()->hook_mem(addr, addr + size - 1, prot_rw,
			[base = addr, name = std::move(name)](vcpu& cpu, const addr_t accessed,
				std::size_t, const mem_prot access)
			{
				// A module-owned address names the global that was touched; anything else --
				// a watched IDT, GDT or TSS -- keeps the label its installer gave it.
				const auto sym = symbols::try_format_addr(cpu, accessed);

				LOG_INFO("0x{:X} accessed {} (type={})", cpu.pc(),
					sym ? *sym : std::format("'{}'+0x{:X}", name, accessed - base),
					static_cast<unsigned>(access));
			});
	}
	catch (const std::exception& e)
	{
		LOG_WARN("cannot watch '{}' at 0x{:X}: {}", name, addr, e.what());
		return nullptr;
	}
}

// A run of T the guest indexes, where emu_object would name only the first element. The whole
// run is one hook, so an access reports the element it landed on.
template <class T>
class emu_object_arr
{
public:
	using value_type = T;

	emu_object_arr() noexcept = default;

	emu_object_arr(addr_space& space, const addr_t addr, const std::size_t count,
		std::string name = {}, const bool monitored = false)
		:	space_(&space), addr_(addr), count_(count), name_(std::move(name))
	{
		if (monitored)
			monitor();
	}

	emu_object_arr(const emu_object_arr& other)
		:	space_(other.space_), addr_(other.addr_), count_(other.count_), name_(other.name_) { }

	emu_object_arr& operator=(const emu_object_arr& other)
	{
		if (this != &other)
		{
			space_ = other.space_; addr_ = other.addr_;
			count_ = other.count_; name_ = other.name_; hook_ = nullptr;
		}
		return *this;
	}

	emu_object_arr(emu_object_arr&& other) noexcept
		:	space_(other.space_), addr_(other.addr_), count_(other.count_),
			hook_(other.hook_), name_(std::move(other.name_))
	{
		other.hook_ = nullptr;
	}

	emu_object_arr& operator=(emu_object_arr&& other) noexcept
	{
		if (this != &other)
		{
			space_ = other.space_; addr_ = other.addr_; count_ = other.count_;
			hook_ = other.hook_; name_ = std::move(other.name_); other.hook_ = nullptr;
		}
		return *this;
	}

	[[nodiscard]] T read(const std::size_t index) const
	{
		return space_->read_mem<T>(element(index));
	}

	void write(const T& val, const std::size_t index)
	{
		space_->write_mem<T>(element(index), val);
	}

	[[nodiscard]] emu_object<T> at(const std::size_t index) const
	{
		return emu_object<T>(*space_, element(index));
	}

	emu_hook* monitor()
	{
		if (hook_ || !space_ || !addr_ || !count_)
			return hook_;

		hook_ = space_->mmu_->emu()->hook_mem(addr_, addr_ + size_bytes() - 1, prot_rw,
			[base = addr_, name = name_](vcpu& cpu, const addr_t accessed,
				std::size_t, const mem_prot access)
			{
				const auto offset = accessed - base;

				LOG_INFO("0x{:X} accessed '{}'[{}]+0x{:X} (type={})",
					cpu.pc(), name, offset / sizeof(T), offset % sizeof(T),
					static_cast<unsigned>(access));
			});

		return hook_;
	}

	[[nodiscard]] bool monitored() const noexcept { return hook_ != nullptr; }
	[[nodiscard]] addr_t address() const noexcept { return addr_; }
	[[nodiscard]] std::size_t count() const noexcept { return count_; }
	[[nodiscard]] std::size_t size_bytes() const noexcept { return count_ * sizeof(T); }
	[[nodiscard]] addr_space* space() const noexcept { return space_; }
	explicit operator bool() const noexcept { return addr_ != 0 && count_ != 0; }

private:
	[[nodiscard]] addr_t element(const std::size_t index) const
	{
		return addr_ + index * sizeof(T);
	}

	addr_space* space_ = nullptr;
	addr_t addr_ = 0;
	std::size_t count_ = 0;
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
