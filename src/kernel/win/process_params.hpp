#pragma once
#include "../../emu/object.hpp"
#include "filesystem.hpp"
#include "string.hpp"
#include <pe.hpp>

constexpr std::string_view  root_dir_narrow     = "C:\\";
constexpr std::string_view  windows_dir_narrow  = "C:\\Windows";
constexpr std::string_view  system32_dir_narrow = "C:\\Windows\\System32\\";
constexpr std::wstring_view windows_dir  = L"C:\\Windows";
constexpr std::wstring_view system32_dir = L"C:\\Windows\\System32\\";

namespace win
{

inline addr_t allocate_environment_block(win_user_mem& mem)
{
	std::wstring env;
	env += L"PATH=";
	env += system32_dir;
	env += L'\0';
	env += L"SystemRoot=";
	env += windows_dir;
	env += L'\0';
	env += L"TEMP=C:\\Users\\Default\\AppData\\Local\\Temp";
	env += L'\0';
	env += L'\0';

	const auto size = env.size() * sizeof(wchar_t);
	const auto addr = mem.alloc(size, prot_rw);
	mem.write_mem(addr, env.data(), size);
	return addr;
}

inline std::wstring_view dir_from_path(std::wstring_view path)
{
	const auto pos = path.find_last_of(L"\\/");
	return pos != std::wstring_view::npos ? path.substr(0, pos + 1) : path;
}

inline emu_object<_RTL_USER_PROCESS_PARAMETERS> init_process_parameters(
	win_user_mem& mem, std::wstring_view image_path)
{
	const auto addr = mem.alloc(sizeof(_RTL_USER_PROCESS_PARAMETERS), prot_rw);
	const auto current_dir = dir_from_path(image_path);

	_RTL_USER_PROCESS_PARAMETERS params{};
	params.MaximumLength = sizeof(_RTL_USER_PROCESS_PARAMETERS);
	params.Length = sizeof(_RTL_USER_PROCESS_PARAMETERS);
	params.Flags = 0x6001;
	params.ConsoleHandle = guest_ptr(~0ULL);

	params.CurrentDirectory.DosPath = init_unicode_string(mem, current_dir);
	params.DllPath = init_unicode_string(mem, system32_dir);
	params.ImagePathName = init_unicode_string(mem, image_path);
	params.CommandLine = init_unicode_string(mem, image_path);
	params.Environment = guest_ptr(allocate_environment_block(mem));

	auto obj = emu_object<_RTL_USER_PROCESS_PARAMETERS>(mem.space(), addr);
	obj.write(params);
	return obj;
}

inline addr_t load_api_set_from_pe(win_user_mem& mem, std::span<const std::uint8_t> data)
{
	if (data.size() < sizeof(pe::dos_header))
		return 0;

	const auto* img = reinterpret_cast<const pe::image*>(data.data());
	if (!img->dos_hdr()->ok())
		return 0;

	for (const auto& sec : img->sections())
	{
		if (sec.name() != ".apiset")
			continue;

		if (!sec.pointer_to_raw_data || !sec.size_of_raw_data)
			break;

		const auto offset = static_cast<std::size_t>(sec.pointer_to_raw_data);
		const auto size = static_cast<std::size_t>(sec.size_of_raw_data);
		if (offset + size > data.size())
			break;

		const auto addr = mem.alloc(size, prot_rw);
		mem.write_mem(addr, data.data() + offset, size);
		return addr;
	}

	return 0;
}

inline addr_t init_api_set_map(win_user_mem& mem, const win_filesystem& fs)
{
	if (const auto file = fs.open(std::string(system32_dir_narrow) + "apisetschema.dll"))
	{
		if (const auto addr = load_api_set_from_pe(mem, file->data()))
			return addr;
	}

	const _API_SET_NAMESPACE ns{
		.Version = 6,
		.Size = sizeof(_API_SET_NAMESPACE),
		.Flags = 0,
		.Count = 0,
		.EntryOffset = sizeof(_API_SET_NAMESPACE),
		.HashOffset = sizeof(_API_SET_NAMESPACE),
		.HashFactor = 0,
	};

	const auto addr = mem.alloc(sizeof(ns), prot_rw);
	mem.write_mem(addr, &ns, sizeof(ns));
	return addr;
}

}
