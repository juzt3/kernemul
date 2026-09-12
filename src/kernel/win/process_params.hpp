#pragma once
#include "../../emu/object.hpp"
#include "string.hpp"

constexpr std::wstring_view system32_dir = L"C:\\Windows\\System32\\";

namespace win
{

inline addr_t allocate_environment_block(addr_space& space)
{
	std::wstring env;
	env += L"PATH=C:\\Windows\\System32";
	env += L'\0';
	env += L"SystemRoot=C:\\Windows";
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

}
