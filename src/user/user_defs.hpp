#pragma once

#include "../kernel/peb_layout.hpp"

#include <cstdint>
#include <cstddef>

// Guest memory layout definitions for usermode Windows x64 structures.
// Based on Vergilius Project / Windows SDK definitions for Windows 10 19041+ x64.
// All pointer fields are std::uint64_t since they represent guest virtual addresses.

namespace user
{

struct list_entry64_t
{
	std::uint64_t Flink;
	std::uint64_t Blink;
};

static_assert(sizeof(list_entry64_t) == 0x10);

struct unicode_string64_t
{
	std::uint16_t Length;
	std::uint16_t MaximumLength;
	std::uint32_t _padding;
	std::uint64_t Buffer;
};

static_assert(sizeof(unicode_string64_t) == 0x10);

struct client_id64_t
{
	std::uint64_t UniqueProcess;
	std::uint64_t UniqueThread;
};

static_assert(sizeof(client_id64_t) == 0x10);

struct nt_tib64_t
{
	std::uint64_t ExceptionList;
	std::uint64_t StackBase;
	std::uint64_t StackLimit;
	std::uint64_t SubSystemTib;
	std::uint64_t FiberData;
	std::uint64_t ArbitraryUserPointer;
	std::uint64_t Self;
};

static_assert(sizeof(nt_tib64_t) == 0x38);
static_assert(offsetof(nt_tib64_t, StackBase) == 0x08);
static_assert(offsetof(nt_tib64_t, StackLimit) == 0x10);
static_assert(offsetof(nt_tib64_t, Self) == 0x30);

struct teb64_t
{
	nt_tib64_t NtTib;                          // 0x00
	std::uint64_t EnvironmentPointer;          // 0x38
	client_id64_t ClientId;                    // 0x40
	std::uint64_t ActiveRpcHandle;             // 0x50
	std::uint64_t ThreadLocalStoragePointer;   // 0x58
	std::uint64_t ProcessEnvironmentBlock;     // 0x60
};

static_assert(offsetof(teb64_t, NtTib.StackBase) == 0x08);
static_assert(offsetof(teb64_t, NtTib.StackLimit) == 0x10);
static_assert(offsetof(teb64_t, NtTib.Self) == 0x30);
static_assert(offsetof(teb64_t, ClientId.UniqueProcess) == 0x40);
static_assert(offsetof(teb64_t, ClientId.UniqueThread) == 0x48);
static_assert(offsetof(teb64_t, ProcessEnvironmentBlock) == 0x60);

constexpr std::size_t teb64_alloc_size = 0x2000;

struct curdir64_t
{
	unicode_string64_t DosPath;
	std::uint64_t Handle;
};

static_assert(sizeof(curdir64_t) == 0x18);

struct rtl_user_process_parameters64_t
{
	std::uint32_t MaximumLength;               // 0x00
	std::uint32_t Length;                      // 0x04
	std::uint32_t Flags;                       // 0x08
	std::uint32_t DebugFlags;                  // 0x0C
	std::uint64_t ConsoleHandle;               // 0x10
	std::uint32_t ConsoleFlags;                // 0x18
	std::uint32_t _pad0;                       // 0x1C
	std::uint64_t StandardInput;               // 0x20
	std::uint64_t StandardOutput;              // 0x28
	std::uint64_t StandardError;               // 0x30
	curdir64_t CurrentDirectory;               // 0x38
	unicode_string64_t DllPath;                // 0x50
	unicode_string64_t ImagePathName;          // 0x60
	unicode_string64_t CommandLine;            // 0x70
	std::uint64_t Environment;                 // 0x80
};

static_assert(offsetof(rtl_user_process_parameters64_t, MaximumLength) == 0x00);
static_assert(offsetof(rtl_user_process_parameters64_t, Length) == 0x04);
static_assert(offsetof(rtl_user_process_parameters64_t, Flags) == 0x08);
static_assert(offsetof(rtl_user_process_parameters64_t, ConsoleHandle) == 0x10);
static_assert(offsetof(rtl_user_process_parameters64_t, StandardInput) == 0x20);
static_assert(offsetof(rtl_user_process_parameters64_t, StandardOutput) == 0x28);
static_assert(offsetof(rtl_user_process_parameters64_t, StandardError) == 0x30);
static_assert(offsetof(rtl_user_process_parameters64_t, CurrentDirectory) == 0x38);
static_assert(offsetof(rtl_user_process_parameters64_t, DllPath) == 0x50);
static_assert(offsetof(rtl_user_process_parameters64_t, ImagePathName) == 0x60);
static_assert(offsetof(rtl_user_process_parameters64_t, CommandLine) == 0x70);
static_assert(offsetof(rtl_user_process_parameters64_t, Environment) == 0x80);

constexpr std::size_t rtl_user_process_parameters64_alloc_size = 0x448;

using ::peb64_t;
using ::peb64_alloc_size;

struct peb_ldr_data64_t
{
	std::uint32_t Length;                      // 0x00
	std::uint8_t Initialized;                 // 0x04
	std::uint8_t _pad0[3];                    // 0x05
	std::uint64_t SsHandle;                   // 0x08
	list_entry64_t InLoadOrderModuleList;      // 0x10
	list_entry64_t InMemoryOrderModuleList;    // 0x20
	list_entry64_t InInitializationOrderModuleList; // 0x30
	std::uint64_t EntryInProgress;             // 0x40
	std::uint8_t ShutdownInProgress;           // 0x48
	std::uint8_t _pad1[7];                    // 0x49
	std::uint64_t ShutdownThreadId;            // 0x50
};

static_assert(sizeof(peb_ldr_data64_t) == 0x58);
static_assert(offsetof(peb_ldr_data64_t, Length) == 0x00);
static_assert(offsetof(peb_ldr_data64_t, Initialized) == 0x04);
static_assert(offsetof(peb_ldr_data64_t, InLoadOrderModuleList) == 0x10);
static_assert(offsetof(peb_ldr_data64_t, InMemoryOrderModuleList) == 0x20);
static_assert(offsetof(peb_ldr_data64_t, InInitializationOrderModuleList) == 0x30);

struct ldr_data_table_entry64_t
{
	list_entry64_t InLoadOrderLinks;           // 0x00
	list_entry64_t InMemoryOrderLinks;         // 0x10
	list_entry64_t InInitializationOrderLinks; // 0x20
	std::uint64_t DllBase;                     // 0x30
	std::uint64_t EntryPoint;                  // 0x38
	std::uint32_t SizeOfImage;                 // 0x40
	std::uint32_t _pad0;                       // 0x44
	unicode_string64_t FullDllName;            // 0x48
	unicode_string64_t BaseDllName;            // 0x58
	std::uint32_t Flags;                       // 0x68
	std::uint16_t ObsoleteLoadCount;           // 0x6C
	std::uint16_t TlsIndex;                    // 0x6E
	list_entry64_t HashLinks;                  // 0x70
};

static_assert(offsetof(ldr_data_table_entry64_t, InLoadOrderLinks) == 0x00);
static_assert(offsetof(ldr_data_table_entry64_t, InMemoryOrderLinks) == 0x10);
static_assert(offsetof(ldr_data_table_entry64_t, InInitializationOrderLinks) == 0x20);
static_assert(offsetof(ldr_data_table_entry64_t, DllBase) == 0x30);
static_assert(offsetof(ldr_data_table_entry64_t, EntryPoint) == 0x38);
static_assert(offsetof(ldr_data_table_entry64_t, SizeOfImage) == 0x40);
static_assert(offsetof(ldr_data_table_entry64_t, FullDllName) == 0x48);
static_assert(offsetof(ldr_data_table_entry64_t, BaseDllName) == 0x58);
static_assert(offsetof(ldr_data_table_entry64_t, Flags) == 0x68);
static_assert(offsetof(ldr_data_table_entry64_t, ObsoleteLoadCount) == 0x6C);
static_assert(offsetof(ldr_data_table_entry64_t, HashLinks) == 0x70);

constexpr std::size_t ldr_data_table_entry64_alloc_size = 0x120;

} // namespace user
