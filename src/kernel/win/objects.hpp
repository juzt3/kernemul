#pragma once
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

// SECTION_ATTRIBUTES, of which only SEC_IMAGE changes what a section is.
inline constexpr std::uint32_t sec_image = 0x01000000;

// A section object body is opaque to the guest apart from its size, which sits
// where the real one keeps it.
inline constexpr std::size_t section_body_size = 0x40;
inline constexpr std::size_t section_body_size_offset = 0x30;
