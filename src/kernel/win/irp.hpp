#pragma once
#include "../../emu/addr_space.hpp"
#include "defs.hpp"
#include "pool.hpp"
#include "status.hpp"
#include "types.hpp"

// What a device request is made of. Building and dispatching one is win_kernel's job; this is
// only the shapes both ends agree on.

// IRP_MJ_*, the index into _DRIVER_OBJECT::MajorFunction a request dispatches through.
enum irp_major : std::uint8_t
{
	irp_mj_create         = 0x00,
	irp_mj_close          = 0x02,
	irp_mj_device_control = 0x0E,
	irp_mj_cleanup        = 0x12,
	irp_mj_maximum        = 0x1B,
};

// How a control code says its buffers reach the driver, held in its bottom two bits.
enum io_method : std::uint32_t
{
	method_buffered   = 0,
	method_in_direct  = 1,
	method_out_direct = 2,
	method_neither    = 3,
};

constexpr io_method control_code_method(const std::uint32_t code)
{
	return static_cast<io_method>(code & 3);
}

// _IRP::Flags, as far as a request built here sets them.
enum irp_flags : std::uint32_t
{
	irp_buffered_io       = 0x00000010,
	irp_deallocate_buffer = 0x00000020,
	irp_input_operation   = 0x00000040,
};

// _IRP::CurrentLocation counts down from StackCount + 1, so a one-deep stack sits at 1 and the
// location itself follows the irp body -- which is what IoGetCurrentIrpStackLocation reads.
inline constexpr std::uint8_t irp_stack_count = 1;

inline constexpr std::uint32_t irp_pool_tag = pool_tag("Irp ");

struct irp_request
{
	std::uint8_t major = irp_mj_device_control;

	addr_t device_object = 0;
	addr_t file_object = 0;

	std::uint32_t control_code = 0;

	// User addresses, read and written through the address space the caller is running in.
	addr_t input_buffer = 0;
	std::uint32_t input_length = 0;
	addr_t output_buffer = 0;
	std::uint32_t output_length = 0;
};

struct irp_result
{
	NTSTATUS status = STATUS_SUCCESS;
	std::uint64_t information = 0;
};

// Pool memory a request borrows, given back however the dispatch leaves -- including the early
// returns, which is what keeps them one line each.
class pool_block
{
public:
	pool_block(win_pool& pool, const std::size_t size, const std::uint32_t tag)
		: pool_(&pool), addr_(size ? pool.allocate(size, tag, true) : 0) {}

	~pool_block() { if (addr_) pool_->free(addr_); }

	pool_block(const pool_block&) = delete;
	pool_block& operator=(const pool_block&) = delete;

	[[nodiscard]] addr_t addr() const noexcept { return addr_; }

private:
	win_pool* pool_;
	addr_t addr_;
};

inline void copy_guest(addr_space& space, const addr_t to, const addr_t from,
	const std::size_t size)
{
	if (!size || !to || !from)
		return;

	std::vector<std::uint8_t> staged(size);
	space.read_mem(from, staged.data(), size);
	space.write_mem(to, staged.data(), size);
}
