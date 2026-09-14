#pragma once
#include "../../emu/defs.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>

class vcpu;
struct proc_module;

// The service table a user process traps through, rebuilt from the two ends
// that are visible: numbers out of the usermode stubs, addresses out of
// ntoskrnl or win32k where the handlers are already bound.
//
// Joining by name rather than reading KiServiceTable keeps the table right
// when the images come from different builds -- the guest issues the numbers
// of the ntdll it was given. win32k's numbers have bit 12 set, so the two
// sources share one map without colliding.
struct win_syscall
{
	virtual ~win_syscall() = default;

	[[nodiscard]] virtual std::uint32_t id(vcpu& cpu) const = 0;

	// The number baked into a stub, if these bytes are one.
	[[nodiscard]] virtual std::optional<std::uint32_t> decode_id(
		std::span<const std::uint8_t> stub) const = 0;

	// Every Nt* export of `image` -- the stub dll laid out as it would be run,
	// in host memory -- against the same name in `impl`. Names `impl` has no
	// symbol for are counted rather than reported: win32k's implementations are
	// spread over images that are not all here.
	void add(std::string_view name, std::span<const std::uint8_t> image,
		const proc_module& impl);

	[[nodiscard]] std::optional<addr_t> find(std::uint32_t id) const;

	[[nodiscard]] std::size_t size() const noexcept { return ids_.size(); }

private:
	std::unordered_map<std::uint32_t, addr_t> ids_;
};

// Null where there is no implementation yet: a guest that traps is then told
// the service is not there.
std::unique_ptr<win_syscall> make_win_syscall();
