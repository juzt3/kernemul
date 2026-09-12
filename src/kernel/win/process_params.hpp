#pragma once
#include "../../emu/object.hpp"
#include "filesystem.hpp"
#include "string.hpp"
#include <pe.hpp>

constexpr std::wstring_view windows_dir  = L"C:\\Windows";
constexpr std::wstring_view system32_dir = L"C:\\Windows\\System32\\";

namespace win
{

inline addr_t allocate_environment_block(addr_space& space)
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
	const auto addr = space.alloc(size, prot_rw);
	space.write_mem(addr, env.data(), size);
	return addr;
}

inline emu_object<_RTL_USER_PROCESS_PARAMETERS64> init_process_parameters(
	addr_space& space, std::string_view name)
{
	const auto addr = space.alloc(rtl_user_process_parameters64_alloc_size, prot_rw);

	const auto wide_name = widen_string(name);
	const auto full_path = std::wstring(system32_dir) + wide_name;

	_RTL_USER_PROCESS_PARAMETERS64 params{};
	params.MaximumLength = rtl_user_process_parameters64_alloc_size;
	params.Length = sizeof(_RTL_USER_PROCESS_PARAMETERS64);
	params.Flags = 0x6001;
	params.ConsoleHandle = ~0ULL;

	params.CurrentDirectory.DosPath = init_unicode_string64(space, system32_dir);
	params.DllPath = init_unicode_string64(space, system32_dir);
	params.ImagePathName = init_unicode_string64(space, full_path);
	params.CommandLine = init_unicode_string64(space, full_path);
	params.Environment = allocate_environment_block(space);

	auto obj = emu_object<_RTL_USER_PROCESS_PARAMETERS64>(space, addr);
	obj.write(params);
	return obj;
}

inline addr_t load_api_set_from_pe(addr_space& space, std::span<const std::uint8_t> data)
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

		const auto addr = space.alloc(size, prot_rw);
		space.write_mem(addr, data.data() + offset, size);
		return addr;
	}

	return 0;
}

inline addr_t init_api_set_map(addr_space& space, const win_filesystem& fs)
{
	if (const auto file = fs.open("C:\\Windows\\System32\\apisetschema.dll"))
	{
		if (const auto addr = load_api_set_from_pe(space, file->data()))
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

	const auto addr = space.alloc(sizeof(ns), prot_rw);
	space.write_mem(addr, &ns, sizeof(ns));
	return addr;
}

}
