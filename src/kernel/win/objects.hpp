#pragma once
#include "dispatcher.hpp"
#include "filesystem.hpp"
#include "win_obj_manager.hpp"

#include <cstdint>
#include <memory>
#include <string>


struct file_host final : win_object
{
	std::shared_ptr<win_file> file;
	std::string path;

	std::uint64_t position = 0;

	// Written to the emulator's own stdout rather than anything in the guest filesystem.
	bool console = false;
};

struct section_host final : win_object
{
	// Null for a pagefile-backed section, whose view starts zeroed and is sized by MaximumSize.
	std::shared_ptr<win_file> file;
	std::string path;
	std::uint64_t size = 0;
	bool is_image = false;
};

struct dispatcher_host final : win_object
{
	win::dispatcher_type type;
	std::string name;

	dispatcher_host(const win::dispatcher_type t, std::string n)
		: type(t), name(std::move(n)) {}
};

inline constexpr std::uint32_t sec_image = 0x01000000;

// Opaque to the guest apart from its size, which sits where the real one keeps it.
inline constexpr std::size_t section_body_size = 0x40;
inline constexpr std::size_t section_body_size_offset = 0x30;
