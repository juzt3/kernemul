#pragma once
#include "dispatcher.hpp"
#include "filesystem.hpp"
#include "win_obj_manager.hpp"

#include <cstdint>
#include <memory>
#include <string>

// Host-side objects that more than one module reaches for. A file is opened by
// the io manager and mapped by the memory manager, so neither owns the type.

struct file_host final : win_object
{
	std::shared_ptr<win_file> file;
	std::string path;

	// Where the next read or write starts, which is what a caller that does not
	// pass a ByteOffset relies on.
	std::uint64_t position = 0;

	// A process's standard output rather than anything in the guest
	// filesystem: what is written to it goes to the emulator's own stdout,
	// because that is the only place a guest can be seen to print.
	bool console = false;
};

struct section_host final : win_object
{
	// Null for a section backed by the pagefile, which is nothing here: the
	// view it maps starts zeroed and is sized by MaximumSize.
	std::shared_ptr<win_file> file;
	std::string path;
	std::uint64_t size = 0;
	bool is_image = false;
};

// A dispatcher object reached by handle. The body behind it is the real KEVENT,
// KSEMAPHORE or KMUTANT, so the Ke* handlers and the Nt* ones see one state; the
// type is what tells a handle for one apart from a handle for another.
struct dispatcher_host final : win_object
{
	win::dispatcher_type type;
	std::string name;

	dispatcher_host(const win::dispatcher_type t, std::string n)
		: type(t), name(std::move(n)) {}
};

// SECTION_ATTRIBUTES, of which only SEC_IMAGE changes what a section is.
inline constexpr std::uint32_t sec_image = 0x01000000;

// A section object body is opaque to the guest apart from its size, which sits
// where the real one keeps it.
inline constexpr std::size_t section_body_size = 0x40;
inline constexpr std::size_t section_body_size_offset = 0x30;
