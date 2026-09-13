#pragma once
#include "defs.hpp"
#include "addr_space.hpp"
#include "mmu.hpp"
#include "emu.hpp"
#include "../util/log.hpp"
#include <cstddef>
#include <type_traits>
#include <typeinfo>
#include <string>

// Where a member sits inside its own type, measured rather than declared: a
// pointer to member says which field without saying where, and offsetof cannot
// be handed one. The storage is never read, only pointed into, and one of it
// exists per type asked about.
template <class C, class M>
[[nodiscard]] std::size_t member_offset(M C::* const member) noexcept
{
	alignas(C) static const std::byte storage[sizeof(C)]{};
	const auto* base = reinterpret_cast<const C*>(storage);

	return static_cast<std::size_t>(
		reinterpret_cast<const std::byte*>(&(base->*member)) - storage);
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

	[[nodiscard]] T read(const std::size_t index = 0) const
	{
		return space_->read_mem<T>(addr_ + index * sizeof(T));
	}

	void write(const T& val, const std::size_t index = 0)
	{
		space_->write_mem<T>(addr_ + index * sizeof(T), val);
	}

	// One field of this object, as an object in its own right: the same address
	// space, the field's own address, and the field's own type. Reading or
	// writing through it touches that field alone rather than carrying the
	// whole structure back and forth -- which matters because the guest owns
	// this memory too, and a write it did not ask for is a write it can see.
	//
	// An array field yields an object of its element type sitting on the first
	// element, so the index read and write already take walks it.
	//
	// The owning class is deduced rather than fixed to T: naming T::* here
	// would be ill-formed for every emu_object over a type that is not a class,
	// emu_object<void*> -- which field() itself hands back -- among them.
	// Requiring it to be T or a base of T is what keeps the member one this
	// object can reach.
	template <class C, class M>
		requires std::is_base_of_v<C, T>
	[[nodiscard]] emu_object<std::remove_extent_t<M>> field(M C::* const member) const
	{
		return emu_object<std::remove_extent_t<M>>(*space_, addr_ + member_offset(member));
	}

	// The same for a field that cannot be named: one whose offset the guest
	// architecture decides, or one the generated type spells only as padding.
	template <class M>
	[[nodiscard]] emu_object<M> field_at(const std::size_t offset) const
	{
		return emu_object<M>(*space_, addr_ + offset);
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
