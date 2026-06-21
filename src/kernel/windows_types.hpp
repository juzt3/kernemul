#pragma once

#ifdef _WIN32
#include <Windows.h>
#include <winternl.h>
#else

#include <cstdint>

using VOID = void;
using UCHAR = std::uint8_t;
using USHORT = std::uint16_t;
using ULONG = std::uint32_t;
using ULONGLONG = std::uint64_t;
using CHAR = char;
using WCHAR = wchar_t;
using SHORT = std::int16_t;
using LONG = std::int32_t;
using LONGLONG = std::int64_t;
using PVOID = void*;
using PCHAR = char*;
using PWSTR = wchar_t*;
using WORD = std::uint16_t;
using DWORD = std::uint32_t;
using BYTE = std::uint8_t;
using BOOLEAN = std::uint8_t;

struct _LIST_ENTRY
{
	_LIST_ENTRY* Flink;
	_LIST_ENTRY* Blink;
};

using LIST_ENTRY = _LIST_ENTRY;
using PLIST_ENTRY = _LIST_ENTRY*;

struct _SINGLE_LIST_ENTRY
{
	_SINGLE_LIST_ENTRY* Next;
};

using SINGLE_LIST_ENTRY = _SINGLE_LIST_ENTRY;

union _LARGE_INTEGER
{
	struct
	{
		ULONG LowPart;
		LONG HighPart;
	};
	LONGLONG QuadPart;
};

using LARGE_INTEGER = _LARGE_INTEGER;

union _ULARGE_INTEGER
{
	struct
	{
		ULONG LowPart;
		ULONG HighPart;
	};
	ULONGLONG QuadPart;
};

using ULARGE_INTEGER = _ULARGE_INTEGER;

struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	WCHAR* Buffer;
};

using UNICODE_STRING = _UNICODE_STRING;

enum _NT_PRODUCT_TYPE
{
	NtProductWinNt = 1,
	NtProductLanManNt = 2,
	NtProductServer = 3
};

enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
	StandardDesign = 0,
	NEC98x86 = 1,
	EndAlternatives = 2
};

struct _NT_TIB
{
	PVOID ExceptionList;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID SubSystemTib;
	PVOID FiberData;
	PVOID ArbitraryUserPointer;
	PVOID Self;
};

using NT_TIB = _NT_TIB;

struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
};

using CLIENT_ID = _CLIENT_ID;

struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		PVOID Pointer;
	};
	ULONGLONG Information;
};

using IO_STATUS_BLOCK = _IO_STATUS_BLOCK;

struct _XSTATE_CONFIGURATION
{
	UCHAR data[0x338];
};

using XSTATE_CONFIGURATION = _XSTATE_CONFIGURATION;

struct M128A
{
	ULONGLONG Low;
	LONGLONG High;
};

struct _XSAVE_FORMAT
{
	USHORT ControlWord;
	USHORT StatusWord;
	UCHAR TagWord;
	UCHAR Reserved1;
	USHORT ErrorOpcode;
	ULONG ErrorOffset;
	USHORT ErrorSelector;
	USHORT Reserved2;
	ULONG DataOffset;
	USHORT DataSelector;
	USHORT Reserved3;
	ULONG MxCsr;
	ULONG MxCsr_Mask;
	M128A FloatRegisters[8];
	M128A XmmRegisters[16];
	UCHAR Reserved4[96];
};

using XSAVE_FORMAT = _XSAVE_FORMAT;
using XMM_SAVE_AREA32 = _XSAVE_FORMAT;

constexpr ULONG CONTEXT_AMD64 = 0x00100000;
constexpr ULONG CONTEXT_CONTROL = CONTEXT_AMD64 | 0x00000001;
constexpr ULONG CONTEXT_INTEGER = CONTEXT_AMD64 | 0x00000002;
constexpr ULONG CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x00000004;
constexpr ULONG CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x00000008;
constexpr ULONG CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010;
constexpr ULONG CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
constexpr ULONG CONTEXT_ALL = CONTEXT_FULL | CONTEXT_SEGMENTS | CONTEXT_DEBUG_REGISTERS;

#pragma pack(push, 16)
struct alignas(16) _CONTEXT
{
	ULONGLONG P1Home;
	ULONGLONG P2Home;
	ULONGLONG P3Home;
	ULONGLONG P4Home;
	ULONGLONG P5Home;
	ULONGLONG P6Home;

	ULONG ContextFlags;
	ULONG MxCsr;

	USHORT SegCs;
	USHORT SegDs;
	USHORT SegEs;
	USHORT SegFs;
	USHORT SegGs;
	USHORT SegSs;
	ULONG EFlags;

	ULONGLONG Dr0;
	ULONGLONG Dr1;
	ULONGLONG Dr2;
	ULONGLONG Dr3;
	ULONGLONG Dr6;
	ULONGLONG Dr7;

	ULONGLONG Rax;
	ULONGLONG Rcx;
	ULONGLONG Rdx;
	ULONGLONG Rbx;
	ULONGLONG Rsp;
	ULONGLONG Rbp;
	ULONGLONG Rsi;
	ULONGLONG Rdi;
	ULONGLONG R8;
	ULONGLONG R9;
	ULONGLONG R10;
	ULONGLONG R11;
	ULONGLONG R12;
	ULONGLONG R13;
	ULONGLONG R14;
	ULONGLONG R15;
	ULONGLONG Rip;

	union
	{
		XMM_SAVE_AREA32 FltSave;
		struct
		{
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		};
	};

	M128A VectorRegister[26];
	ULONGLONG VectorControl;

	ULONGLONG DebugControl;
	ULONGLONG LastBranchToRip;
	ULONGLONG LastBranchFromRip;
	ULONGLONG LastExceptionToRip;
	ULONGLONG LastExceptionFromRip;
};
#pragma pack(pop)

using CONTEXT = _CONTEXT;

constexpr ULONG EXCEPTION_MAXIMUM_PARAMETERS = 15;

struct _EXCEPTION_RECORD
{
	ULONG ExceptionCode;
	ULONG ExceptionFlags;
	_EXCEPTION_RECORD* ExceptionRecord;
	PVOID ExceptionAddress;
	ULONG NumberParameters;
	ULONGLONG ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
};

using EXCEPTION_RECORD = _EXCEPTION_RECORD;

using HANDLE = void*;

struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	_UNICODE_STRING* ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
};

using OBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES;

using PCONTEXT = _CONTEXT*;

struct _RUNTIME_FUNCTION
{
	ULONG BeginAddress;
	ULONG EndAddress;
	ULONG UnwindData;
};

using RUNTIME_FUNCTION = _RUNTIME_FUNCTION;
using PRUNTIME_FUNCTION = _RUNTIME_FUNCTION*;

using EXCEPTION_DISPOSITION = int;
using PEXCEPTION_ROUTINE = PVOID;

struct _DISPATCHER_CONTEXT
{
	ULONGLONG ControlPc;
	ULONGLONG ImageBase;
	PRUNTIME_FUNCTION FunctionEntry;
	ULONGLONG EstablisherFrame;
	ULONGLONG TargetIp;
	PCONTEXT ContextRecord;
	PEXCEPTION_ROUTINE LanguageHandler;
	PVOID HandlerData;
	PVOID HistoryTable;
	ULONG ScopeIndex;
};

using DISPATCHER_CONTEXT = _DISPATCHER_CONTEXT;

struct _OSVERSIONINFOW
{
	ULONG dwOSVersionInfoSize;
	ULONG dwMajorVersion;
	ULONG dwMinorVersion;
	ULONG dwBuildNumber;
	ULONG dwPlatformId;
	WCHAR szCSDVersion[128];
};

using OSVERSIONINFOW = _OSVERSIONINFOW;

struct _OSVERSIONINFOEXW
{
	ULONG dwOSVersionInfoSize;
	ULONG dwMajorVersion;
	ULONG dwMinorVersion;
	ULONG dwBuildNumber;
	ULONG dwPlatformId;
	WCHAR szCSDVersion[128];
	USHORT wServicePackMajor;
	USHORT wServicePackMinor;
	USHORT wSuiteMask;
	UCHAR wProductType;
	UCHAR wReserved;
};

using OSVERSIONINFOEXW = _OSVERSIONINFOEXW;

constexpr ULONG VER_PLATFORM_WIN32_NT = 2;

struct IMAGE_DOS_HEADER
{
	USHORT e_magic;
	USHORT e_cblp;
	USHORT e_cp;
	USHORT e_crlc;
	USHORT e_cparhdr;
	USHORT e_minalloc;
	USHORT e_maxalloc;
	USHORT e_ss;
	USHORT e_sp;
	USHORT e_csum;
	USHORT e_ip;
	USHORT e_cs;
	USHORT e_lfarlc;
	USHORT e_ovno;
	USHORT e_res[4];
	USHORT e_oemid;
	USHORT e_oeminfo;
	USHORT e_res2[10];
	LONG e_lfanew;
};

struct IMAGE_FILE_HEADER
{
	USHORT Machine;
	USHORT NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
};

struct IMAGE_DATA_DIRECTORY
{
	ULONG VirtualAddress;
	ULONG Size;
};

struct IMAGE_OPTIONAL_HEADER64
{
	USHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	ULONG SizeOfCode;
	ULONG SizeOfInitializedData;
	ULONG SizeOfUninitializedData;
	ULONG AddressOfEntryPoint;
	ULONG BaseOfCode;
	ULONGLONG ImageBase;
	ULONG SectionAlignment;
	ULONG FileAlignment;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	USHORT MajorImageVersion;
	USHORT MinorImageVersion;
	USHORT MajorSubsystemVersion;
	USHORT MinorSubsystemVersion;
	ULONG Win32VersionValue;
	ULONG SizeOfImage;
	ULONG SizeOfHeaders;
	ULONG CheckSum;
	USHORT Subsystem;
	USHORT DllCharacteristics;
	ULONGLONG SizeOfStackReserve;
	ULONGLONG SizeOfStackCommit;
	ULONGLONG SizeOfHeapReserve;
	ULONGLONG SizeOfHeapCommit;
	ULONG LoaderFlags;
	ULONG NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS64
{
	ULONG Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct IMAGE_SECTION_HEADER
{
	UCHAR Name[8];
	union
	{
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT NumberOfRelocations;
	USHORT NumberOfLinenumbers;
	ULONG Characteristics;
};

constexpr ULONG IMAGE_SCN_MEM_EXECUTE = 0x20000000;

#define IMAGE_FIRST_SECTION(nt_headers) \
	reinterpret_cast<const IMAGE_SECTION_HEADER*>( \
		reinterpret_cast<const char*>(&(nt_headers)->OptionalHeader) + \
		(nt_headers)->FileHeader.SizeOfOptionalHeader)

#endif // !_WIN32
