#pragma once
#include <Windows.h>
#include <winternl.h>

//0x10 bytes (sizeof)
struct _TIME_FIELDS
{
    SHORT Year;                                                             //0x0
    SHORT Month;                                                            //0x2
    SHORT Day;                                                              //0x4
    SHORT Hour;                                                             //0x6
    SHORT Minute;                                                           //0x8
    SHORT Second;                                                           //0xa
    SHORT Milliseconds;                                                     //0xc
    SHORT Weekday;                                                          //0xe
};

//0x150 bytes (sizeof)
struct _DRIVER_OBJECT
{
    SHORT Type;                                                             //0x0
    SHORT Size;                                                             //0x2
    struct _DEVICE_OBJECT* DeviceObject;                                    //0x8
    ULONG Flags;                                                            //0x10
    VOID* DriverStart;                                                      //0x18
    ULONG DriverSize;                                                       //0x20
    VOID* DriverSection;                                                    //0x28
    struct _DRIVER_EXTENSION* DriverExtension;                              //0x30
    struct _UNICODE_STRING DriverName;                                      //0x38
    struct _UNICODE_STRING* HardwareDatabase;                               //0x48
    struct _FAST_IO_DISPATCH* FastIoDispatch;                               //0x50
    LONG(*DriverInit)(struct _DRIVER_OBJECT* arg1, struct _UNICODE_STRING* arg2); //0x58
    VOID(*DriverStartIo)(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2);  //0x60
    VOID(*DriverUnload)(struct _DRIVER_OBJECT* arg1);                      //0x68
    LONG(*MajorFunction[28])(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2); //0x70
};

//0xc bytes (sizeof)
struct _KSYSTEM_TIME
{
    ULONG LowPart;                                                          //0x0
    LONG High1Time;                                                         //0x4
    LONG High2Time;                                                         //0x8
};

//0x720 bytes (sizeof)
struct _KUSER_SHARED_DATA
{
    ULONG TickCountLowDeprecated;                                           //0x0
    ULONG TickCountMultiplier;                                              //0x4
    volatile struct _KSYSTEM_TIME InterruptTime;                            //0x8
    volatile struct _KSYSTEM_TIME SystemTime;                               //0x14
    volatile struct _KSYSTEM_TIME TimeZoneBias;                             //0x20
    USHORT ImageNumberLow;                                                  //0x2c
    USHORT ImageNumberHigh;                                                 //0x2e
    WCHAR NtSystemRoot[260];                                                //0x30
    ULONG MaxStackTraceDepth;                                               //0x238
    ULONG CryptoExponent;                                                   //0x23c
    ULONG TimeZoneId;                                                       //0x240
    ULONG LargePageMinimum;                                                 //0x244
    ULONG AitSamplingValue;                                                 //0x248
    ULONG AppCompatFlag;                                                    //0x24c
    ULONGLONG RNGSeedVersion;                                               //0x250
    ULONG GlobalValidationRunlevel;                                         //0x258
    volatile LONG TimeZoneBiasStamp;                                        //0x25c
    ULONG NtBuildNumber;                                                    //0x260
    enum _NT_PRODUCT_TYPE NtProductType;                                    //0x264
    UCHAR ProductTypeIsValid;                                               //0x268
    UCHAR Reserved0[1];                                                     //0x269
    USHORT NativeProcessorArchitecture;                                     //0x26a
    ULONG NtMajorVersion;                                                   //0x26c
    ULONG NtMinorVersion;                                                   //0x270
    UCHAR ProcessorFeatures[64];                                            //0x274
    ULONG Reserved1;                                                        //0x2b4
    ULONG Reserved3;                                                        //0x2b8
    volatile ULONG TimeSlip;                                                //0x2bc
    enum _ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;            //0x2c0
    ULONG BootId;                                                           //0x2c4
    union _LARGE_INTEGER SystemExpirationDate;                              //0x2c8
    ULONG SuiteMask;                                                        //0x2d0
    UCHAR KdDebuggerEnabled;                                                //0x2d4
    union
    {
        UCHAR MitigationPolicies;                                           //0x2d5
        struct
        {
            UCHAR NXSupportPolicy : 2;                                        //0x2d5
            UCHAR SEHValidationPolicy : 2;                                    //0x2d5
            UCHAR CurDirDevicesSkippedForDlls : 2;                            //0x2d5
            UCHAR Reserved : 2;                                               //0x2d5
        };
    };
    USHORT CyclesPerYield;                                                  //0x2d6
    volatile ULONG ActiveConsoleId;                                         //0x2d8
    volatile ULONG DismountCount;                                           //0x2dc
    ULONG ComPlusPackage;                                                   //0x2e0
    ULONG LastSystemRITEventTickCount;                                      //0x2e4
    ULONG NumberOfPhysicalPages;                                            //0x2e8
    UCHAR SafeBootMode;                                                     //0x2ec
    UCHAR VirtualizationFlags;                                              //0x2ed
    UCHAR Reserved12[2];                                                    //0x2ee
    union
    {
        ULONG SharedDataFlags;                                              //0x2f0
        struct
        {
            ULONG DbgErrorPortPresent : 1;                                    //0x2f0
            ULONG DbgElevationEnabled : 1;                                    //0x2f0
            ULONG DbgVirtEnabled : 1;                                         //0x2f0
            ULONG DbgInstallerDetectEnabled : 1;                              //0x2f0
            ULONG DbgLkgEnabled : 1;                                          //0x2f0
            ULONG DbgDynProcessorEnabled : 1;                                 //0x2f0
            ULONG DbgConsoleBrokerEnabled : 1;                                //0x2f0
            ULONG DbgSecureBootEnabled : 1;                                   //0x2f0
            ULONG DbgMultiSessionSku : 1;                                     //0x2f0
            ULONG DbgMultiUsersInSessionSku : 1;                              //0x2f0
            ULONG DbgStateSeparationEnabled : 1;                              //0x2f0
            ULONG SpareBits : 21;                                             //0x2f0
        };
    };
    ULONG DataFlagsPad[1];                                                  //0x2f4
    ULONGLONG TestRetInstruction;                                           //0x2f8
    LONGLONG QpcFrequency;                                                  //0x300
    ULONG SystemCall;                                                       //0x308
    ULONG Reserved2;                                                        //0x30c
    ULONGLONG SystemCallPad[2];                                             //0x310
    union
    {
        volatile struct _KSYSTEM_TIME TickCount;                            //0x320
        volatile ULONGLONG TickCountQuad;                                   //0x320
        ULONG ReservedTickCountOverlay[3];                                  //0x320
    };
    ULONG TickCountPad[1];                                                  //0x32c
    ULONG Cookie;                                                           //0x330
    ULONG CookiePad[1];                                                     //0x334
    LONGLONG ConsoleSessionForegroundProcessId;                             //0x338
    ULONGLONG TimeUpdateLock;                                               //0x340
    ULONGLONG BaselineSystemTimeQpc;                                        //0x348
    ULONGLONG BaselineInterruptTimeQpc;                                     //0x350
    ULONGLONG QpcSystemTimeIncrement;                                       //0x358
    ULONGLONG QpcInterruptTimeIncrement;                                    //0x360
    UCHAR QpcSystemTimeIncrementShift;                                      //0x368
    UCHAR QpcInterruptTimeIncrementShift;                                   //0x369
    USHORT UnparkedProcessorCount;                                          //0x36a
    ULONG EnclaveFeatureMask[4];                                            //0x36c
    ULONG TelemetryCoverageRound;                                           //0x37c
    USHORT UserModeGlobalLogger[16];                                        //0x380
    ULONG ImageFileExecutionOptions;                                        //0x3a0
    ULONG LangGenerationCount;                                              //0x3a4
    ULONGLONG Reserved4;                                                    //0x3a8
    volatile ULONGLONG InterruptTimeBias;                                   //0x3b0
    volatile ULONGLONG QpcBias;                                             //0x3b8
    ULONG ActiveProcessorCount;                                             //0x3c0
    volatile UCHAR ActiveGroupCount;                                        //0x3c4
    UCHAR Reserved9;                                                        //0x3c5
    union
    {
        USHORT QpcData;                                                     //0x3c6
        struct
        {
            volatile UCHAR QpcBypassEnabled;                                //0x3c6
            UCHAR QpcShift;                                                 //0x3c7
        };
    };
    union _LARGE_INTEGER TimeZoneBiasEffectiveStart;                        //0x3c8
    union _LARGE_INTEGER TimeZoneBiasEffectiveEnd;                          //0x3d0
    struct _XSTATE_CONFIGURATION XState;                                    //0x3d8
    struct _KSYSTEM_TIME FeatureConfigurationChangeStamp;                   //0x710
    ULONG Spare;                                                            //0x71c
};

//0x18 bytes (sizeof)
struct _DISPATCHER_HEADER
{
	union
	{
		volatile LONG Lock;                                                     //0x0
		struct
		{
			UCHAR Type;                                                         //0x0
			UCHAR Signalling;                                                   //0x1
			UCHAR Size;                                                         //0x2
			UCHAR Reserved1;                                                    //0x3
		};
	};
	LONG SignalState;                                                           //0x4
	struct _LIST_ENTRY WaitListHead;                                            //0x8
};

//0x18 bytes (sizeof)
struct _KEVENT
{
	struct _DISPATCHER_HEADER Header;                                           //0x0
};

//0x40 bytes (sizeof)
struct _KTIMER
{
	struct _DISPATCHER_HEADER Header;                                           //0x0
	union _ULARGE_INTEGER DueTime;                                              //0x18
	struct _LIST_ENTRY TimerListEntry;                                          //0x20
	struct _KDPC* Dpc;                                                          //0x30
	ULONG Processor;                                                            //0x38
	ULONG Period;                                                               //0x3c
};

//0x18 bytes (sizeof)
struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            struct _RTL_BALANCED_NODE* Left;                                //0x0
            struct _RTL_BALANCED_NODE* Right;                               //0x8
        };
    };
    union
    {
        struct
        {
            UCHAR Red : 1;                                                    //0x10
            UCHAR Balance : 2;                                                //0x10
        };
        ULONGLONG ParentValue;                                              //0x10
    };
};

//0xa0 bytes (sizeof)
struct _KLDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    VOID* ExceptionTable;                                                   //0x10
    ULONG ExceptionTableSize;                                               //0x18
    VOID* GpValue;                                                          //0x20
    struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    ULONG Flags;                                                            //0x68
    USHORT LoadCount;                                                       //0x6c
    union
    {
        USHORT SignatureLevel : 4;                                            //0x6e
        USHORT SignatureType : 3;                                             //0x6e
        USHORT Unused : 9;                                                    //0x6e
        USHORT EntireField;                                                 //0x6e
    } u1;                                                                   //0x6e
    VOID* SectionPointer;                                                   //0x70
    ULONG CheckSum;                                                         //0x78
    ULONG CoverageSectionSize;                                              //0x7c
    VOID* CoverageSection;                                                  //0x80
    VOID* LoadedImports;                                                    //0x88
    VOID* Spare;                                                            //0x90
    ULONG SizeOfImageNotRounded;                                            //0x98
    ULONG TimeDateStamp;                                                    //0x9c
};

//0x178 bytes (sizeof)
struct _KPCR
{
    union
    {
        struct _NT_TIB NtTib;                                               //0x0
        struct
        {
            union _KGDTENTRY64* GdtBase;                                    //0x0
            struct _KTSS64* TssBase;                                        //0x8
            ULONGLONG UserRsp;                                              //0x10
            struct _KPCR* Self;                                             //0x18
            struct _KPRCB* CurrentPrcb;                                     //0x20
            struct _KSPIN_LOCK_QUEUE* LockArray;                            //0x28
            VOID* Used_Self;                                                //0x30
        };
    };
    union _KIDTENTRY64* IdtBase;                                            //0x38
    ULONGLONG Unused[2];                                                    //0x40
    UCHAR Irql;                                                             //0x50
    UCHAR SecondLevelCacheAssociativity;                                    //0x51
    UCHAR ObsoleteNumber;                                                   //0x52
    UCHAR Fill0;                                                            //0x53
    ULONG Unused0[3];                                                       //0x54
    USHORT MajorVersion;                                                    //0x60
    USHORT MinorVersion;                                                    //0x62
    ULONG StallScaleFactor;                                                 //0x64
    VOID* Unused1[3];                                                       //0x68
    ULONG KernelReserved[15];                                               //0x80
    ULONG SecondLevelCacheSize;                                             //0xbc
    ULONG HalReserved[16];                                                  //0xc0
    ULONG Unused2;                                                          //0x100
    VOID* KdVersionBlock;                                                   //0x108
    VOID* Unused3;                                                          //0x110
    ULONG PcrAlign1[24];                                                    //0x118
};

//0x10 bytes (sizeof)
struct _KDESCRIPTOR
{
    USHORT Pad[3];                                                          //0x0
    USHORT Limit;                                                           //0x6
    VOID* Base;                                                             //0x8
};

//0xf0 bytes (sizeof)
struct _KSPECIAL_REGISTERS
{
    ULONGLONG Cr0;                                                          //0x0
    ULONGLONG Cr2;                                                          //0x8
    ULONGLONG Cr3;                                                          //0x10
    ULONGLONG Cr4;                                                          //0x18
    ULONGLONG KernelDr0;                                                    //0x20
    ULONGLONG KernelDr1;                                                    //0x28
    ULONGLONG KernelDr2;                                                    //0x30
    ULONGLONG KernelDr3;                                                    //0x38
    ULONGLONG KernelDr6;                                                    //0x40
    ULONGLONG KernelDr7;                                                    //0x48
    struct _KDESCRIPTOR Gdtr;                                               //0x50
    struct _KDESCRIPTOR Idtr;                                               //0x60
    USHORT Tr;                                                              //0x70
    USHORT Ldtr;                                                            //0x72
    ULONG MxCsr;                                                            //0x74
    ULONGLONG DebugControl;                                                 //0x78
    ULONGLONG LastBranchToRip;                                              //0x80
    ULONGLONG LastBranchFromRip;                                            //0x88
    ULONGLONG LastExceptionToRip;                                           //0x90
    ULONGLONG LastExceptionFromRip;                                         //0x98
    ULONGLONG Cr8;                                                          //0xa0
    ULONGLONG MsrGsBase;                                                    //0xa8
    ULONGLONG MsrGsSwap;                                                    //0xb0
    ULONGLONG MsrStar;                                                      //0xb8
    ULONGLONG MsrLStar;                                                     //0xc0
    ULONGLONG MsrCStar;                                                     //0xc8
    ULONGLONG MsrSyscallMask;                                               //0xd0
    ULONGLONG Xcr0;                                                         //0xd8
    ULONGLONG MsrFsBase;                                                    //0xe0
    ULONGLONG SpecialPadding0;                                              //0xe8
};

//0x5c0 bytes (sizeof)
struct _KPROCESSOR_STATE
{
    struct _KSPECIAL_REGISTERS SpecialRegisters;                            //0x0
    struct _CONTEXT ContextFrame;                                           //0xf0
};

//0x700 bytes (sizeof)
struct _KPRCB
{
    ULONG MxCsr;                                                            //0x0
    UCHAR LegacyNumber;                                                     //0x4
    UCHAR ReservedMustBeZero;                                               //0x5
    UCHAR InterruptRequest;                                                 //0x6
    UCHAR IdleHalt;                                                         //0x7
    struct _KTHREAD* CurrentThread;                                         //0x8
    struct _KTHREAD* NextThread;                                            //0x10
    struct _KTHREAD* IdleThread;                                            //0x18
    UCHAR NestingLevel;                                                     //0x20
    UCHAR ClockOwner;                                                       //0x21
    union
    {
        UCHAR PendingTickFlags;                                             //0x22
        struct
        {
            UCHAR PendingTick : 1;                                            //0x22
            UCHAR PendingBackupTick : 1;                                      //0x22
        };
    };
    UCHAR IdleState;                                                        //0x23
    ULONG Number;                                                           //0x24
    ULONGLONG RspBase;                                                      //0x28
    ULONGLONG PrcbLock;                                                     //0x30
    CHAR* PriorityState;                                                    //0x38
    CHAR CpuType;                                                           //0x40
    CHAR CpuID;                                                             //0x41
    union
    {
        USHORT CpuStep;                                                     //0x42
        struct
        {
            UCHAR CpuStepping;                                              //0x42
            UCHAR CpuModel;                                                 //0x43
        };
    };
    ULONG MHz;                                                              //0x44
    ULONGLONG HalReserved[8];                                               //0x48
    USHORT MinorVersion;                                                    //0x88
    USHORT MajorVersion;                                                    //0x8a
    UCHAR BuildType;                                                        //0x8c
    UCHAR CpuVendor;                                                        //0x8d
    UCHAR LegacyCoresPerPhysicalProcessor;                                  //0x8e
    UCHAR LegacyLogicalProcessorsPerCore;                                   //0x8f
    ULONGLONG TscFrequency;                                                 //0x90
    ULONG CoresPerPhysicalProcessor;                                        //0x98
    ULONG LogicalProcessorsPerCore;                                         //0x9c
    ULONGLONG PrcbPad04[4];                                                 //0xa0
    struct _KNODE* ParentNode;                                              //0xc0
    ULONGLONG GroupSetMember;                                               //0xc8
    UCHAR Group;                                                            //0xd0
    UCHAR GroupIndex;                                                       //0xd1
    UCHAR PrcbPad05[2];                                                     //0xd2
    ULONG InitialApicId;                                                    //0xd4
    ULONG ScbOffset;                                                        //0xd8
    ULONG ApicMask;                                                         //0xdc
    VOID* AcpiReserved;                                                     //0xe0
    ULONG CFlushSize;                                                       //0xe8
    ULONGLONG PrcbPad11[2];                                                 //0xf0
    struct _KPROCESSOR_STATE ProcessorState;                                //0x100
    struct _XSAVE_AREA_HEADER* ExtendedSupervisorState;                     //0x6c0
    ULONG ProcessorSignature;                                               //0x6c8
    ULONG ProcessorFlags;                                                   //0x6cc
    ULONGLONG PrcbPad12a;                                                   //0x6d0
    ULONGLONG PrcbPad12[3];                                                 //0x6d8
};

//0x108 bytes (sizeof)
struct _KAFFINITY_EX
{
    USHORT Count;                                                           //0x0
    USHORT Size;                                                            //0x2
    ULONG Reserved;                                                         //0x4
    union
    {
        ULONGLONG Bitmap[1];                                                //0x8
        ULONGLONG StaticBitmap[32];                                         //0x8
    };
};

//0x1 bytes (sizeof)
union _KEXECUTE_OPTIONS
{
    UCHAR ExecuteDisable : 1;                                                 //0x0
    UCHAR ExecuteEnable : 1;                                                  //0x0
    UCHAR DisableThunkEmulation : 1;                                          //0x0
    UCHAR Permanent : 1;                                                      //0x0
    UCHAR ExecuteDispatchEnable : 1;                                          //0x0
    UCHAR ImageDispatchEnable : 1;                                            //0x0
    UCHAR DisableExceptionChainValidation : 1;                                //0x0
    UCHAR Spare : 1;                                                          //0x0
    volatile UCHAR ExecuteOptions;                                          //0x0
    UCHAR ExecuteOptionsNV;                                                 //0x0
};

//0x4 bytes (sizeof)
union _KSTACK_COUNT
{
    LONG Value;                                                             //0x0
    ULONG State : 3;                                                          //0x0
    ULONG StackCount : 29;                                                    //0x0
};

//0x438 bytes (sizeof)
struct _KPROCESS
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;                                           //0x28
    struct _LIST_ENTRY ThreadListHead;                                      //0x30
    ULONG ProcessLock;                                                      //0x40
    ULONG ProcessTimerDelay;                                                //0x44
    ULONGLONG DeepFreezeStartTime;                                          //0x48
    struct _KAFFINITY_EX Affinity;                                          //0x50
    struct _LIST_ENTRY ReadyListHead;                                       //0x158
    struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x168
    volatile struct _KAFFINITY_EX ActiveProcessors;                         //0x170
    union
    {
        struct
        {
            ULONG AutoAlignment : 1;                                          //0x278
            ULONG DisableBoost : 1;                                           //0x278
            ULONG DisableQuantum : 1;                                         //0x278
            ULONG DeepFreeze : 1;                                             //0x278
            ULONG TimerVirtualization : 1;                                    //0x278
            ULONG CheckStackExtents : 1;                                      //0x278
            ULONG CacheIsolationEnabled : 1;                                  //0x278
            ULONG PpmPolicy : 4;                                              //0x278
            ULONG VaSpaceDeleted : 1;                                         //0x278
            ULONG MultiGroup : 1;                                             //0x278
            ULONG ReservedFlags : 19;                                         //0x278
        };
        volatile LONG ProcessFlags;                                         //0x278
    };
    ULONG ActiveGroupsMask;                                                 //0x27c
    CHAR BasePriority;                                                      //0x280
    CHAR QuantumReset;                                                      //0x281
    CHAR Visited;                                                           //0x282
    union _KEXECUTE_OPTIONS Flags;                                          //0x283
    USHORT ThreadSeed[32];                                                  //0x284
    USHORT IdealProcessor[32];                                              //0x2c4
    USHORT IdealNode[32];                                                   //0x304
    USHORT IdealGlobalNode;                                                 //0x344
    USHORT Spare1;                                                          //0x346
    volatile _KSTACK_COUNT StackCount;                                 //0x348
    struct _LIST_ENTRY ProcessListEntry;                                    //0x350
    ULONGLONG CycleTime;                                                    //0x360
    ULONGLONG ContextSwitches;                                              //0x368
    struct _KSCHEDULING_GROUP* SchedulingGroup;                             //0x370
    ULONG FreezeCount;                                                      //0x378
    ULONG KernelTime;                                                       //0x37c
    ULONG UserTime;                                                         //0x380
    ULONG ReadyTime;                                                        //0x384
    ULONGLONG UserDirectoryTableBase;                                       //0x388
    UCHAR AddressPolicy;                                                    //0x390
    UCHAR Spare2[71];                                                       //0x391
    VOID* InstrumentationCallback;                                          //0x3d8
    union
    {
        ULONGLONG SecureHandle;                                             //0x3e0
        struct
        {
            ULONGLONG SecureProcess : 1;                                      //0x3e0
            ULONGLONG Unused : 1;                                             //0x3e0
        } Flags;                                                            //0x3e0
    } SecureState;                                                          //0x3e0
    ULONGLONG KernelWaitTime;                                               //0x3e8
    ULONGLONG UserWaitTime;                                                 //0x3f0
    ULONGLONG LastRebalanceQpc;                                             //0x3f8
    VOID* PerProcessorCycleTimes;                                           //0x400
    ULONGLONG ExtendedFeatureDisableMask;                                   //0x408
    USHORT PrimaryGroup;                                                    //0x410
    USHORT Spare3[3];                                                       //0x412
    VOID* UserCetLogging;                                                   //0x418
    struct _LIST_ENTRY CpuPartitionList;                                    //0x420
    ULONGLONG EndPadding[1];                                                //0x430
};

//0x8 bytes (sizeof)
struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked : 1;                                             //0x0
            ULONGLONG Waiting : 1;                                            //0x0
            ULONGLONG Waking : 1;                                             //0x0
            ULONGLONG MultipleShared : 1;                                     //0x0
            ULONGLONG Shared : 60;                                            //0x0
        };
        ULONGLONG Value;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};

//0x8 bytes (sizeof)
struct _EX_RUNDOWN_REF
{
    union
    {
        ULONGLONG Count;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};

//0x8 bytes (sizeof)
struct _EX_FAST_REF
{
    union
    {
        VOID* Object;                                                       //0x0
        ULONGLONG RefCnt : 4;                                                 //0x0
        ULONGLONG Value;                                                    //0x0
    };
};

//0x8 bytes (sizeof)
struct _RTL_AVL_TREE
{
    struct _RTL_BALANCED_NODE* Root;                                        //0x0
};

//0x8 bytes (sizeof)
struct _SE_AUDIT_PROCESS_CREATION_INFO
{
    struct _OBJECT_NAME_INFORMATION* ImageFileName;                         //0x0
};

//0x4 bytes (sizeof)
struct _MMSUPPORT_FLAGS
{
    union
    {
        struct
        {
            UCHAR WorkingSetType : 3;                                         //0x0
            UCHAR Reserved0 : 3;                                              //0x0
            UCHAR MaximumWorkingSetHard : 1;                                  //0x0
            UCHAR MinimumWorkingSetHard : 1;                                  //0x0
            UCHAR SessionMaster : 1;                                          //0x1
            UCHAR TrimmerState : 2;                                           //0x1
            UCHAR Reserved : 1;                                               //0x1
            UCHAR PageStealers : 4;                                           //0x1
        };
        USHORT u1;                                                          //0x0
    };
    UCHAR MemoryPriority;                                                   //0x2
    union
    {
        struct
        {
            UCHAR WsleDeleted : 1;                                            //0x3
            UCHAR SvmEnabled : 1;                                             //0x3
            UCHAR ForceAge : 1;                                               //0x3
            UCHAR ForceTrim : 1;                                              //0x3
            UCHAR NewMaximum : 1;                                             //0x3
            UCHAR CommitReleaseState : 2;                                     //0x3
        };
        UCHAR u2;                                                           //0x3
    };
};

//0xc0 bytes (sizeof)
struct _MMSUPPORT_INSTANCE
{
    ULONG NextPageColor;                                                    //0x0
    volatile ULONG PageFaultCount;                                          //0x4
    ULONGLONG TrimmedPageCount;                                             //0x8
    struct _MMWSL_INSTANCE* VmWorkingSetList;                               //0x10
    struct _LIST_ENTRY WorkingSetExpansionLinks;                            //0x18
    volatile ULONGLONG AgeDistribution[8];                                  //0x28
    struct _KGATE* ExitOutswapGate;                                         //0x68
    ULONGLONG MinimumWorkingSetSize;                                        //0x70
    ULONGLONG MaximumWorkingSetSize;                                        //0x78
    volatile ULONGLONG WorkingSetLeafSize;                                  //0x80
    volatile ULONGLONG WorkingSetLeafPrivateSize;                           //0x88
    volatile ULONGLONG WorkingSetSize;                                      //0x90
    volatile ULONGLONG WorkingSetPrivateSize;                               //0x98
    ULONGLONG PeakWorkingSetSize;                                           //0xa0
    ULONG HardFaultCount;                                                   //0xa8
    USHORT LastTrimStamp;                                                   //0xac
    USHORT PartitionId;                                                     //0xae
    ULONGLONG SelfmapLock;                                                  //0xb0
    struct _MMSUPPORT_FLAGS Flags;                                          //0xb8
    LONG InterlockedFlags;                                                  //0xbc
};

//0x80 bytes (sizeof)
struct _MMSUPPORT_SHARED
{
    volatile LONG WorkingSetLock;                                           //0x0
    LONG GoodCitizenWaiting;                                                //0x4
    ULONGLONG ReleasedCommitDebt;                                           //0x8
    ULONGLONG ResetPagesRepurposedCount;                                    //0x10
    VOID* WsSwapSupport;                                                    //0x18
    VOID* CommitReleaseContext;                                             //0x20
    VOID* AccessLog;                                                        //0x28
    volatile ULONGLONG ChargedWslePages;                                    //0x30
    ULONGLONG ActualWslePages;                                              //0x38
    volatile LONG WorkingSetCoreLock;                                       //0x40
    VOID* ShadowMapping;                                                    //0x48
};

//0x140 bytes (sizeof)
struct _MMSUPPORT_FULL
{
    struct _MMSUPPORT_INSTANCE Instance;                                    //0x0
    struct _MMSUPPORT_SHARED Shared;                                        //0xc0
};

//0x20 bytes (sizeof)
struct _ALPC_PROCESS_CONTEXT
{
    struct _EX_PUSH_LOCK Lock;                                              //0x0
    struct _LIST_ENTRY ViewListHead;                                        //0x8
    volatile ULONGLONG PagedPoolQuotaCache;                                 //0x18
};

//0x1 bytes (sizeof)
struct _PS_PROTECTION
{
    union
    {
        UCHAR Level;                                                        //0x0
        struct
        {
            UCHAR Type : 3;                                                   //0x0
            UCHAR Audit : 1;                                                  //0x0
            UCHAR Signer : 4;                                                 //0x0
        };
    };
};

//0x8 bytes (sizeof)
union _PS_INTERLOCKED_TIMER_DELAY_VALUES
{
    ULONGLONG DelayMs : 30;                                                   //0x0
    ULONGLONG CoalescingWindowMs : 30;                                        //0x0
    ULONGLONG Reserved : 1;                                                   //0x0
    ULONGLONG NewTimerWheel : 1;                                              //0x0
    ULONGLONG Retry : 1;                                                      //0x0
    ULONGLONG Locked : 1;                                                     //0x0
    ULONGLONG All;                                                          //0x0
};

//0x8 bytes (sizeof)
struct _WNF_STATE_NAME
{
    ULONG Data[2];                                                          //0x0
};

//0x8 bytes (sizeof)
struct _JOBOBJECT_WAKE_FILTER
{
    ULONG HighEdgeFilter;                                                   //0x0
    ULONG LowEdgeFilter;                                                    //0x4
};

//0x30 bytes (sizeof)
struct _PS_PROCESS_WAKE_INFORMATION
{
    ULONGLONG NotificationChannel;                                          //0x0
    ULONG WakeCounters[7];                                                  //0x8
    struct _JOBOBJECT_WAKE_FILTER WakeFilter;                               //0x24
    ULONG NoWakeCounter;                                                    //0x2c
};

//0x4 bytes (sizeof)
union _KE_PROCESS_CONCURRENCY_COUNT
{
    ULONG Fraction : 20;                                                      //0x0
    ULONG Count : 12;                                                         //0x0
    ULONG AllFields;                                                        //0x0
};

//0x8 bytes (sizeof)
struct _KE_IDEAL_PROCESSOR_SET_BREAKPOINTS
{
    union _KE_PROCESS_CONCURRENCY_COUNT Low;                                //0x0
    union _KE_PROCESS_CONCURRENCY_COUNT High;                               //0x4
};

//0x118 bytes (sizeof)
struct _KE_IDEAL_PROCESSOR_ASSIGNMENT_BLOCK
{
    union _KE_PROCESS_CONCURRENCY_COUNT ExpectedConcurrencyCount;           //0x0
    struct _KE_IDEAL_PROCESSOR_SET_BREAKPOINTS Breakpoints;                 //0x4
    union
    {
        ULONG ConcurrencyCountFixed : 1;                                      //0xc
        ULONG AllFlags;                                                     //0xc
    } AssignmentFlags;                                                      //0xc
    struct _KAFFINITY_EX IdealProcessorSets;                                //0x10
};

//0x10 bytes (sizeof)
struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
{
    struct _RTL_AVL_TREE Tree;                                              //0x0
    struct _EX_PUSH_LOCK Lock;                                              //0x8
};

//0x8 bytes (sizeof)
struct _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT
{
    ULONG Level;                                                            //0x0
    ULONG Slot;                                                             //0x4
};

//0xb80 bytes (sizeof)
struct _EPROCESS
{
    struct _KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK ProcessLock;                                       //0x438
    VOID* UniqueProcessId;                                                  //0x440
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x448
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x458
    union
    {
        ULONG Flags2;                                                       //0x460
        struct
        {
            ULONG JobNotReallyActive : 1;                                     //0x460
            ULONG AccountingFolded : 1;                                       //0x460
            ULONG NewProcessReported : 1;                                     //0x460
            ULONG ExitProcessReported : 1;                                    //0x460
            ULONG ReportCommitChanges : 1;                                    //0x460
            ULONG LastReportMemory : 1;                                       //0x460
            ULONG ForceWakeCharge : 1;                                        //0x460
            ULONG CrossSessionCreate : 1;                                     //0x460
            ULONG NeedsHandleRundown : 1;                                     //0x460
            ULONG RefTraceEnabled : 1;                                        //0x460
            ULONG PicoCreated : 1;                                            //0x460
            ULONG EmptyJobEvaluated : 1;                                      //0x460
            ULONG DefaultPagePriority : 3;                                    //0x460
            ULONG PrimaryTokenFrozen : 1;                                     //0x460
            ULONG ProcessVerifierTarget : 1;                                  //0x460
            ULONG RestrictSetThreadContext : 1;                               //0x460
            ULONG AffinityPermanent : 1;                                      //0x460
            ULONG AffinityUpdateEnable : 1;                                   //0x460
            ULONG PropagateNode : 1;                                          //0x460
            ULONG ExplicitAffinity : 1;                                       //0x460
            ULONG ProcessExecutionState : 2;                                  //0x460
            ULONG EnableReadVmLogging : 1;                                    //0x460
            ULONG EnableWriteVmLogging : 1;                                   //0x460
            ULONG FatalAccessTerminationRequested : 1;                        //0x460
            ULONG DisableSystemAllowedCpuSet : 1;                             //0x460
            ULONG ProcessStateChangeRequest : 2;                              //0x460
            ULONG ProcessStateChangeInProgress : 1;                           //0x460
            ULONG InPrivate : 1;                                              //0x460
        };
    };
    union
    {
        ULONG Flags;                                                        //0x464
        struct
        {
            ULONG CreateReported : 1;                                         //0x464
            ULONG NoDebugInherit : 1;                                         //0x464
            ULONG ProcessExiting : 1;                                         //0x464
            ULONG ProcessDelete : 1;                                          //0x464
            ULONG ManageExecutableMemoryWrites : 1;                           //0x464
            ULONG VmDeleted : 1;                                              //0x464
            ULONG OutswapEnabled : 1;                                         //0x464
            ULONG Outswapped : 1;                                             //0x464
            ULONG FailFastOnCommitFail : 1;                                   //0x464
            ULONG Wow64VaSpace4Gb : 1;                                        //0x464
            ULONG AddressSpaceInitialized : 2;                                //0x464
            ULONG SetTimerResolution : 1;                                     //0x464
            ULONG BreakOnTermination : 1;                                     //0x464
            ULONG DeprioritizeViews : 1;                                      //0x464
            ULONG WriteWatch : 1;                                             //0x464
            ULONG ProcessInSession : 1;                                       //0x464
            ULONG OverrideAddressSpace : 1;                                   //0x464
            ULONG HasAddressSpace : 1;                                        //0x464
            ULONG LaunchPrefetched : 1;                                       //0x464
            ULONG Reserved : 1;                                               //0x464
            ULONG VmTopDown : 1;                                              //0x464
            ULONG ImageNotifyDone : 1;                                        //0x464
            ULONG PdeUpdateNeeded : 1;                                        //0x464
            ULONG VdmAllowed : 1;                                             //0x464
            ULONG ProcessRundown : 1;                                         //0x464
            ULONG ProcessInserted : 1;                                        //0x464
            ULONG DefaultIoPriority : 3;                                      //0x464
            ULONG ProcessSelfDelete : 1;                                      //0x464
            ULONG SetTimerResolutionLink : 1;                                 //0x464
        };
    };
    union _LARGE_INTEGER CreateTime;                                        //0x468
    ULONGLONG ProcessQuotaUsage[2];                                         //0x470
    ULONGLONG ProcessQuotaPeak[2];                                          //0x480
    ULONGLONG PeakVirtualSize;                                              //0x490
    ULONGLONG VirtualSize;                                                  //0x498
    struct _LIST_ENTRY SessionProcessLinks;                                 //0x4a0
    union
    {
        VOID* ExceptionPortData;                                            //0x4b0
        ULONGLONG ExceptionPortValue;                                       //0x4b0
        ULONGLONG ExceptionPortState : 3;                                     //0x4b0
    };
    struct _EX_FAST_REF Token;                                              //0x4b8
    ULONGLONG MmReserved;                                                   //0x4c0
    struct _EX_PUSH_LOCK AddressCreationLock;                               //0x4c8
    struct _EX_PUSH_LOCK PageTableCommitmentLock;                           //0x4d0
    struct _ETHREAD* RotateInProgress;                                      //0x4d8
    struct _ETHREAD* ForkInProgress;                                        //0x4e0
    struct _EJOB* volatile CommitChargeJob;                                 //0x4e8
    struct _RTL_AVL_TREE CloneRoot;                                         //0x4f0
    volatile ULONGLONG NumberOfPrivatePages;                                //0x4f8
    volatile ULONGLONG NumberOfLockedPages;                                 //0x500
    VOID* Win32Process;                                                     //0x508
    struct _EJOB* volatile Job;                                             //0x510
    VOID* SectionObject;                                                    //0x518
    VOID* SectionBaseAddress;                                               //0x520
    ULONG Cookie;                                                           //0x528
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x530
    VOID* Win32WindowStation;                                               //0x538
    VOID* InheritedFromUniqueProcessId;                                     //0x540
    volatile ULONGLONG OwnerProcessId;                                      //0x548
    struct _PEB* Peb;                                                       //0x550
    struct _MM_SESSION_SPACE* Session;                                      //0x558
    VOID* Spare1;                                                           //0x560
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0x568
    struct _HANDLE_TABLE* ObjectTable;                                      //0x570
    VOID* DebugPort;                                                        //0x578
    struct _EWOW64PROCESS* WoW64Process;                                    //0x580
    struct _EX_FAST_REF DeviceMap;                                          //0x588
    VOID* EtwDataSource;                                                    //0x590
    ULONGLONG PageDirectoryPte;                                             //0x598
    struct _FILE_OBJECT* ImageFilePointer;                                  //0x5a0
    UCHAR ImageFileName[15];                                                //0x5a8
    UCHAR PriorityClass;                                                    //0x5b7
    VOID* SecurityPort;                                                     //0x5b8
    struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;      //0x5c0
    struct _LIST_ENTRY JobLinks;                                            //0x5c8
    VOID* HighestUserAddress;                                               //0x5d8
    struct _LIST_ENTRY ThreadListHead;                                      //0x5e0
    volatile ULONG ActiveThreads;                                           //0x5f0
    ULONG ImagePathHash;                                                    //0x5f4
    ULONG DefaultHardErrorProcessing;                                       //0x5f8
    LONG LastThreadExitStatus;                                              //0x5fc
    struct _EX_FAST_REF PrefetchTrace;                                      //0x600
    VOID* LockedPagesList;                                                  //0x608
    union _LARGE_INTEGER ReadOperationCount;                                //0x610
    union _LARGE_INTEGER WriteOperationCount;                               //0x618
    union _LARGE_INTEGER OtherOperationCount;                               //0x620
    union _LARGE_INTEGER ReadTransferCount;                                 //0x628
    union _LARGE_INTEGER WriteTransferCount;                                //0x630
    union _LARGE_INTEGER OtherTransferCount;                                //0x638
    ULONGLONG CommitChargeLimit;                                            //0x640
    volatile ULONGLONG CommitCharge;                                        //0x648
    volatile ULONGLONG CommitChargePeak;                                    //0x650
    struct _MMSUPPORT_FULL Vm;                                              //0x680
    struct _LIST_ENTRY MmProcessLinks;                                      //0x7c0
    ULONG ModifiedPageCount;                                                //0x7d0
    LONG ExitStatus;                                                        //0x7d4
    struct _RTL_AVL_TREE VadRoot;                                           //0x7d8
    VOID* VadHint;                                                          //0x7e0
    ULONGLONG VadCount;                                                     //0x7e8
    volatile ULONGLONG VadPhysicalPages;                                    //0x7f0
    ULONGLONG VadPhysicalPagesLimit;                                        //0x7f8
    struct _ALPC_PROCESS_CONTEXT AlpcContext;                               //0x800
    struct _LIST_ENTRY TimerResolutionLink;                                 //0x820
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x830
    ULONG RequestedTimerResolution;                                         //0x838
    ULONG SmallestTimerResolution;                                          //0x83c
    union _LARGE_INTEGER ExitTime;                                          //0x840
    struct _INVERTED_FUNCTION_TABLE_KERNEL_MODE* InvertedFunctionTable;     //0x848
    struct _EX_PUSH_LOCK InvertedFunctionTableLock;                         //0x850
    ULONG ActiveThreadsHighWatermark;                                       //0x858
    ULONG LargePrivateVadCount;                                             //0x85c
    struct _EX_PUSH_LOCK ThreadListLock;                                    //0x860
    VOID* WnfContext;                                                       //0x868
    struct _EJOB* ServerSilo;                                               //0x870
    UCHAR SignatureLevel;                                                   //0x878
    UCHAR SectionSignatureLevel;                                            //0x879
    struct _PS_PROTECTION Protection;                                       //0x87a
    UCHAR HangCount : 3;                                                      //0x87b
    UCHAR GhostCount : 3;                                                     //0x87b
    UCHAR PrefilterException : 1;                                             //0x87b
    union
    {
        ULONG Flags3;                                                       //0x87c
        struct
        {
            ULONG Minimal : 1;                                                //0x87c
            ULONG ReplacingPageRoot : 1;                                      //0x87c
            ULONG Crashed : 1;                                                //0x87c
            ULONG JobVadsAreTracked : 1;                                      //0x87c
            ULONG VadTrackingDisabled : 1;                                    //0x87c
            ULONG AuxiliaryProcess : 1;                                       //0x87c
            ULONG SubsystemProcess : 1;                                       //0x87c
            ULONG IndirectCpuSets : 1;                                        //0x87c
            ULONG RelinquishedCommit : 1;                                     //0x87c
            ULONG HighGraphicsPriority : 1;                                   //0x87c
            ULONG CommitFailLogged : 1;                                       //0x87c
            ULONG ReserveFailLogged : 1;                                      //0x87c
            ULONG SystemProcess : 1;                                          //0x87c
            ULONG HideImageBaseAddresses : 1;                                 //0x87c
            ULONG AddressPolicyFrozen : 1;                                    //0x87c
            ULONG ProcessFirstResume : 1;                                     //0x87c
            ULONG ForegroundExternal : 1;                                     //0x87c
            ULONG ForegroundSystem : 1;                                       //0x87c
            ULONG HighMemoryPriority : 1;                                     //0x87c
            ULONG EnableProcessSuspendResumeLogging : 1;                      //0x87c
            ULONG EnableThreadSuspendResumeLogging : 1;                       //0x87c
            ULONG SecurityDomainChanged : 1;                                  //0x87c
            ULONG SecurityFreezeComplete : 1;                                 //0x87c
            ULONG VmProcessorHost : 1;                                        //0x87c
            ULONG VmProcessorHostTransition : 1;                              //0x87c
            ULONG AltSyscall : 1;                                             //0x87c
            ULONG TimerResolutionIgnore : 1;                                  //0x87c
            ULONG DisallowUserTerminate : 1;                                  //0x87c
            ULONG EnableProcessRemoteExecProtectVmLogging : 1;                //0x87c
            ULONG EnableProcessLocalExecProtectVmLogging : 1;                 //0x87c
            ULONG MemoryCompressionProcess : 1;                               //0x87c
        };
    };
    LONG DeviceAsid;                                                        //0x880
    VOID* SvmData;                                                          //0x888
    struct _EX_PUSH_LOCK SvmProcessLock;                                    //0x890
    ULONGLONG SvmLock;                                                      //0x898
    struct _LIST_ENTRY SvmProcessDeviceListHead;                            //0x8a0
    ULONGLONG LastFreezeInterruptTime;                                      //0x8b0
    struct _PROCESS_DISK_COUNTERS* DiskCounters;                            //0x8b8
    VOID* PicoContext;                                                      //0x8c0
    VOID* EnclaveTable;                                                     //0x8c8
    ULONGLONG EnclaveNumber;                                                //0x8d0
    struct _EX_PUSH_LOCK EnclaveLock;                                       //0x8d8
    ULONG HighPriorityFaultsAllowed;                                        //0x8e0
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;                       //0x8e8
    VOID* VmContext;                                                        //0x8f0
    ULONGLONG SequenceNumber;                                               //0x8f8
    ULONGLONG CreateInterruptTime;                                          //0x900
    ULONGLONG CreateUnbiasedInterruptTime;                                  //0x908
    ULONGLONG TotalUnbiasedFrozenTime;                                      //0x910
    ULONGLONG LastAppStateUpdateTime;                                       //0x918
    ULONGLONG LastAppStateUptime : 61;                                        //0x920
    ULONGLONG LastAppState : 3;                                               //0x920
    volatile ULONGLONG SharedCommitCharge;                                  //0x928
    struct _EX_PUSH_LOCK SharedCommitLock;                                  //0x930
    struct _LIST_ENTRY SharedCommitLinks;                                   //0x938
    union
    {
        struct
        {
            ULONGLONG AllowedCpuSets;                                       //0x948
            ULONGLONG DefaultCpuSets;                                       //0x950
        };
        struct
        {
            ULONGLONG* AllowedCpuSetsIndirect;                              //0x948
            ULONGLONG* DefaultCpuSetsIndirect;                              //0x950
        };
    };
    VOID* DiskIoAttribution;                                                //0x958
    VOID* DxgProcess;                                                       //0x960
    ULONG Win32KFilterSet;                                                  //0x968
    USHORT Machine;                                                         //0x96c
    USHORT Spare0;                                                          //0x96e
    volatile _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;     //0x970
    volatile ULONG KTimerSets;                                              //0x978
    volatile ULONG KTimer2Sets;                                             //0x97c
    volatile ULONG ThreadTimerSets;                                         //0x980
    ULONGLONG VirtualTimerListLock;                                         //0x988
    struct _LIST_ENTRY VirtualTimerListHead;                                //0x990
    union
    {
        struct _WNF_STATE_NAME WakeChannel;                                 //0x9a0
        struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;                       //0x9a0
    };
    union
    {
        ULONG MitigationFlags;                                              //0x9d0
        struct
        {
            ULONG ControlFlowGuardEnabled : 1;                                //0x9d0
            ULONG ControlFlowGuardExportSuppressionEnabled : 1;               //0x9d0
            ULONG ControlFlowGuardStrict : 1;                                 //0x9d0
            ULONG DisallowStrippedImages : 1;                                 //0x9d0
            ULONG ForceRelocateImages : 1;                                    //0x9d0
            ULONG HighEntropyASLREnabled : 1;                                 //0x9d0
            ULONG StackRandomizationDisabled : 1;                             //0x9d0
            ULONG ExtensionPointDisable : 1;                                  //0x9d0
            ULONG DisableDynamicCode : 1;                                     //0x9d0
            ULONG DisableDynamicCodeAllowOptOut : 1;                          //0x9d0
            ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;                 //0x9d0
            ULONG AuditDisableDynamicCode : 1;                                //0x9d0
            ULONG DisallowWin32kSystemCalls : 1;                              //0x9d0
            ULONG AuditDisallowWin32kSystemCalls : 1;                         //0x9d0
            ULONG EnableFilteredWin32kAPIs : 1;                               //0x9d0
            ULONG AuditFilteredWin32kAPIs : 1;                                //0x9d0
            ULONG DisableNonSystemFonts : 1;                                  //0x9d0
            ULONG AuditNonSystemFontLoading : 1;                              //0x9d0
            ULONG PreferSystem32Images : 1;                                   //0x9d0
            ULONG ProhibitRemoteImageMap : 1;                                 //0x9d0
            ULONG AuditProhibitRemoteImageMap : 1;                            //0x9d0
            ULONG ProhibitLowILImageMap : 1;                                  //0x9d0
            ULONG AuditProhibitLowILImageMap : 1;                             //0x9d0
            ULONG SignatureMitigationOptIn : 1;                               //0x9d0
            ULONG AuditBlockNonMicrosoftBinaries : 1;                         //0x9d0
            ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1;               //0x9d0
            ULONG LoaderIntegrityContinuityEnabled : 1;                       //0x9d0
            ULONG AuditLoaderIntegrityContinuity : 1;                         //0x9d0
            ULONG EnableModuleTamperingProtection : 1;                        //0x9d0
            ULONG EnableModuleTamperingProtectionNoInherit : 1;               //0x9d0
            ULONG RestrictIndirectBranchPrediction : 1;                       //0x9d0
            ULONG IsolateSecurityDomain : 1;                                  //0x9d0
        } MitigationFlagsValues;                                            //0x9d0
    };
    union
    {
        ULONG MitigationFlags2;                                             //0x9d4
        struct
        {
            ULONG EnableExportAddressFilter : 1;                              //0x9d4
            ULONG AuditExportAddressFilter : 1;                               //0x9d4
            ULONG EnableExportAddressFilterPlus : 1;                          //0x9d4
            ULONG AuditExportAddressFilterPlus : 1;                           //0x9d4
            ULONG EnableRopStackPivot : 1;                                    //0x9d4
            ULONG AuditRopStackPivot : 1;                                     //0x9d4
            ULONG EnableRopCallerCheck : 1;                                   //0x9d4
            ULONG AuditRopCallerCheck : 1;                                    //0x9d4
            ULONG EnableRopSimExec : 1;                                       //0x9d4
            ULONG AuditRopSimExec : 1;                                        //0x9d4
            ULONG EnableImportAddressFilter : 1;                              //0x9d4
            ULONG AuditImportAddressFilter : 1;                               //0x9d4
            ULONG DisablePageCombine : 1;                                     //0x9d4
            ULONG SpeculativeStoreBypassDisable : 1;                          //0x9d4
            ULONG CetUserShadowStacks : 1;                                    //0x9d4
            ULONG AuditCetUserShadowStacks : 1;                               //0x9d4
            ULONG AuditCetUserShadowStacksLogged : 1;                         //0x9d4
            ULONG UserCetSetContextIpValidation : 1;                          //0x9d4
            ULONG AuditUserCetSetContextIpValidation : 1;                     //0x9d4
            ULONG AuditUserCetSetContextIpValidationLogged : 1;               //0x9d4
            ULONG CetUserShadowStacksStrictMode : 1;                          //0x9d4
            ULONG BlockNonCetBinaries : 1;                                    //0x9d4
            ULONG BlockNonCetBinariesNonEhcont : 1;                           //0x9d4
            ULONG AuditBlockNonCetBinaries : 1;                               //0x9d4
            ULONG AuditBlockNonCetBinariesLogged : 1;                         //0x9d4
            ULONG XtendedControlFlowGuard : 1;                                //0x9d4
            ULONG AuditXtendedControlFlowGuard : 1;                           //0x9d4
            ULONG PointerAuthUserIp : 1;                                      //0x9d4
            ULONG AuditPointerAuthUserIp : 1;                                 //0x9d4
            ULONG AuditPointerAuthUserIpLogged : 1;                           //0x9d4
            ULONG CetDynamicApisOutOfProcOnly : 1;                            //0x9d4
            ULONG UserCetSetContextIpValidationRelaxedMode : 1;               //0x9d4
        } MitigationFlags2Values;                                           //0x9d4
    };
    VOID* PartitionObject;                                                  //0x9d8
    ULONGLONG SecurityDomain;                                               //0x9e0
    ULONGLONG ParentSecurityDomain;                                         //0x9e8
    VOID* CoverageSamplerContext;                                           //0x9f0
    VOID* MmHotPatchContext;                                                //0x9f8
    struct _KE_IDEAL_PROCESSOR_ASSIGNMENT_BLOCK IdealProcessorAssignmentBlock; //0xa00
    struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree;                  //0xb18
    struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock;                  //0xb20
    struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges; //0xb28
    ULONG DisabledComponentFlags;                                           //0xb38
    volatile LONG PageCombineSequence;                                      //0xb3c
    struct _EX_PUSH_LOCK EnableOptionalXStateFeaturesLock;                  //0xb40
    ULONG* volatile PathRedirectionHashes;                                  //0xb48
    struct _PS_SYSCALL_PROVIDER* SyscallProvider;                           //0xb50
    struct _LIST_ENTRY SyscallProviderProcessLinks;                         //0xb58
    struct _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT SyscallProviderDispatchContext; //0xb68
    union
    {
        ULONG MitigationFlags3;                                             //0xb70
        struct
        {
            ULONG RestrictCoreSharing : 1;                                    //0xb70
            ULONG MitigationFlags3Spare : 31;                                 //0xb70
        } MitigationFlags3Values;                                           //0xb70
    };
};

//0x1 bytes (sizeof)
union _KWAIT_STATUS_REGISTER
{
    UCHAR Flags;                                                            //0x0
    UCHAR State : 3;                                                          //0x0
    UCHAR Affinity : 1;                                                       //0x0
    UCHAR Priority : 1;                                                       //0x0
    UCHAR Apc : 1;                                                            //0x0
    UCHAR UserApc : 1;                                                        //0x0
    UCHAR Alert : 1;                                                          //0x0
};

//0x30 bytes (sizeof)
struct _KAPC_STATE
{
    struct _LIST_ENTRY ApcListHead[2];                                      //0x0
    struct _KPROCESS* Process;                                              //0x20
    union
    {
        UCHAR InProgressFlags;                                              //0x28
        struct
        {
            UCHAR KernelApcInProgress : 1;                                    //0x28
            UCHAR SpecialApcInProgress : 1;                                   //0x28
        };
    };
    UCHAR KernelApcPending;                                                 //0x29
    union
    {
        UCHAR UserApcPendingAll;                                            //0x2a
        struct
        {
            UCHAR SpecialUserApcPending : 1;                                  //0x2a
            UCHAR UserApcPending : 1;                                         //0x2a
        };
    };
};

//0x58 bytes (sizeof)
struct _KAPC
{
    UCHAR Type;                                                             //0x0
    union
    {
        UCHAR AllFlags;                                                     //0x1
        struct
        {
            UCHAR CallbackDataContext : 1;                                    //0x1
            UCHAR Unused : 7;                                                 //0x1
        };
    };
    UCHAR Size;                                                             //0x2
    UCHAR SpareByte1;                                                       //0x3
    ULONG SpareLong0;                                                       //0x4
    struct _KTHREAD* Thread;                                                //0x8
    struct _LIST_ENTRY ApcListEntry;                                        //0x10
    union
    {
        struct
        {
            VOID(*KernelRoutine)(struct _KAPC* arg1, VOID(**arg2)(VOID* arg1, VOID* arg2, VOID* arg3), VOID** arg3, VOID** arg4, VOID** arg5); //0x20
            VOID(*RundownRoutine)(struct _KAPC* arg1);                     //0x28
            VOID(*NormalRoutine)(VOID* arg1, VOID* arg2, VOID* arg3);      //0x30
        };
        VOID* Reserved[3];                                                  //0x20
    };
    VOID* NormalContext;                                                    //0x38
    VOID* SystemArgument1;                                                  //0x40
    VOID* SystemArgument2;                                                  //0x48
    CHAR ApcStateIndex;                                                     //0x50
    CHAR ApcMode;                                                           //0x51
    UCHAR Inserted;                                                         //0x52
};

//0x8 bytes (sizeof)
union _KERNEL_SHADOW_STACK_LIMIT
{
    ULONGLONG AllFields;                                                    //0x0
    ULONGLONG ShadowStackType : 3;                                            //0x0
    ULONGLONG Unused : 9;                                                     //0x0
    ULONGLONG ShadowStackLimitPfn : 52;                                       //0x0
};

//0x30 bytes (sizeof)
struct _KWAIT_BLOCK
{
    struct _LIST_ENTRY WaitListEntry;                                       //0x0
    UCHAR WaitType;                                                         //0x10
    volatile UCHAR BlockState;                                              //0x11
    USHORT WaitKey;                                                         //0x12
    LONG SpareLong;                                                         //0x14
    union
    {
        struct _KTHREAD* Thread;                                            //0x18
        struct _KQUEUE* NotificationQueue;                                  //0x18
        struct _KDPC* Dpc;                                                  //0x18
    };
    VOID* Object;                                                           //0x20
    VOID* SparePtr;                                                         //0x28
};

//0x480 bytes (sizeof)
struct _KTHREAD
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    VOID* SListFaultAddress;                                                //0x18
    ULONGLONG QuantumTarget;                                                //0x20
    VOID* InitialStack;                                                     //0x28
    VOID* volatile StackLimit;                                              //0x30
    VOID* StackBase;                                                        //0x38
    ULONGLONG ThreadLock;                                                   //0x40
    volatile ULONGLONG CycleTime;                                           //0x48
    ULONG CurrentRunTime;                                                   //0x50
    ULONG ExpectedRunTime;                                                  //0x54
    VOID* KernelStack;                                                      //0x58
    struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
    struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
    union _KWAIT_STATUS_REGISTER WaitRegister;                              //0x70
    volatile UCHAR Running;                                                 //0x71
    UCHAR Alerted[2];                                                       //0x72
    union
    {
        struct
        {
            ULONG AutoBoostActive : 1;                                        //0x74
            ULONG ReadyTransition : 1;                                        //0x74
            ULONG WaitNext : 1;                                               //0x74
            ULONG SystemAffinityActive : 1;                                   //0x74
            ULONG Alertable : 1;                                              //0x74
            ULONG UserStackWalkActive : 1;                                    //0x74
            ULONG ApcInterruptRequest : 1;                                    //0x74
            ULONG QuantumEndMigrate : 1;                                      //0x74
            ULONG SecureThread : 1;                                           //0x74
            ULONG TimerActive : 1;                                            //0x74
            ULONG SystemThread : 1;                                           //0x74
            ULONG ProcessDetachActive : 1;                                    //0x74
            ULONG CalloutActive : 1;                                          //0x74
            ULONG ScbReadyQueue : 1;                                          //0x74
            ULONG ApcQueueable : 1;                                           //0x74
            ULONG ReservedStackInUse : 1;                                     //0x74
            ULONG Spare : 1;                                                  //0x74
            ULONG TimerSuspended : 1;                                         //0x74
            ULONG SuspendedWaitMode : 1;                                      //0x74
            ULONG SuspendSchedulerApcWait : 1;                                //0x74
            ULONG CetUserShadowStack : 1;                                     //0x74
            ULONG BypassProcessFreeze : 1;                                    //0x74
            ULONG CetKernelShadowStack : 1;                                   //0x74
            ULONG StateSaveAreaDecoupled : 1;                                 //0x74
            ULONG Reserved : 8;                                               //0x74
        };
        LONG MiscFlags;                                                     //0x74
    };
    union
    {
        struct
        {
            ULONG UserIdealProcessorFixed : 1;                                //0x78
            ULONG IsolationWidth : 1;                                         //0x78
            ULONG AutoAlignment : 1;                                          //0x78
            ULONG DisableBoost : 1;                                           //0x78
            ULONG AlertedByThreadId : 1;                                      //0x78
            ULONG QuantumDonation : 1;                                        //0x78
            ULONG EnableStackSwap : 1;                                        //0x78
            ULONG GuiThread : 1;                                              //0x78
            ULONG DisableQuantum : 1;                                         //0x78
            ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
            ULONG DeferPreemption : 1;                                        //0x78
            ULONG QueueDeferPreemption : 1;                                   //0x78
            ULONG ForceDeferSchedule : 1;                                     //0x78
            ULONG SharedReadyQueueAffinity : 1;                               //0x78
            ULONG FreezeCount : 1;                                            //0x78
            ULONG TerminationApcRequest : 1;                                  //0x78
            ULONG AutoBoostEntriesExhausted : 1;                              //0x78
            ULONG KernelStackResident : 1;                                    //0x78
            ULONG TerminateRequestReason : 2;                                 //0x78
            ULONG ProcessStackCountDecremented : 1;                           //0x78
            ULONG RestrictedGuiThread : 1;                                    //0x78
            ULONG VpBackingThread : 1;                                        //0x78
            ULONG EtwStackTraceCrimsonApcDisabled : 1;                        //0x78
            ULONG EtwStackTraceApcInserted : 8;                               //0x78
        };
        volatile LONG ThreadFlags;                                          //0x78
    };
    volatile UCHAR Tag;                                                     //0x7c
    UCHAR SystemHeteroCpuPolicy;                                            //0x7d
    UCHAR UserHeteroCpuPolicy : 7;                                            //0x7e
    UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
    union
    {
        struct
        {
            UCHAR RunningNonRetpolineCode : 1;                                //0x7f
            UCHAR SpecCtrlSpare : 7;                                          //0x7f
        };
        UCHAR SpecCtrl;                                                     //0x7f
    };
    ULONG SystemCallNumber;                                                 //0x80
    ULONG ReadyTime;                                                        //0x84
    VOID* FirstArgument;                                                    //0x88
    struct _KTRAP_FRAME* TrapFrame;                                         //0x90
    union
    {
        struct _KAPC_STATE ApcState;                                        //0x98
        struct
        {
            UCHAR ApcStateFill[43];                                         //0x98
            CHAR Priority;                                                  //0xc3
            ULONG UserIdealProcessor;                                       //0xc4
        };
    };
    volatile LONGLONG WaitStatus;                                           //0xc8
    struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
    union
    {
        struct _LIST_ENTRY WaitListEntry;                                   //0xd8
        struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
    };
    struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
    VOID* Teb;                                                              //0xf0
    ULONGLONG RelativeTimerBias;                                            //0xf8
    struct _KTIMER Timer;                                                   //0x100
    union
    {
        struct _KWAIT_BLOCK WaitBlock[4];                                   //0x140
        struct
        {
            UCHAR WaitBlockFill4[20];                                       //0x140
            ULONG ContextSwitches;                                          //0x154
        };
        struct
        {
            UCHAR WaitBlockFill5[68];                                       //0x140
            volatile UCHAR State;                                           //0x184
            CHAR Spare13;                                                   //0x185
            UCHAR WaitIrql;                                                 //0x186
            CHAR WaitMode;                                                  //0x187
        };
        struct
        {
            UCHAR WaitBlockFill6[116];                                      //0x140
            ULONG WaitTime;                                                 //0x1b4
        };
        struct
        {
            UCHAR WaitBlockFill7[164];                                      //0x140
            union
            {
                struct
                {
                    SHORT KernelApcDisable;                                 //0x1e4
                    SHORT SpecialApcDisable;                                //0x1e6
                };
                ULONG CombinedApcDisable;                                   //0x1e4
            };
        };
        struct
        {
            UCHAR WaitBlockFill8[40];                                       //0x140
            struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
        };
        struct
        {
            UCHAR WaitBlockFill9[88];                                       //0x140
            struct _XSTATE_SAVE* XStateSave;                                //0x198
        };
        struct
        {
            UCHAR WaitBlockFill10[136];                                     //0x140
            VOID* volatile Win32Thread;                                     //0x1c8
        };
        struct
        {
            UCHAR WaitBlockFill11[176];                                     //0x140
            ULONGLONG Spare18;                                              //0x1f0
            ULONGLONG Spare19;                                              //0x1f8
        };
    };
    union
    {
        volatile LONG ThreadFlags2;                                         //0x200
        struct
        {
            ULONG BamQosLevel : 8;                                            //0x200
            ULONG ThreadFlags2Reserved : 24;                                  //0x200
        };
    };
    UCHAR HgsFeedbackClass;                                                 //0x204
    UCHAR Spare23[3];                                                       //0x205
    struct _LIST_ENTRY QueueListEntry;                                      //0x208
    union
    {
        volatile ULONG NextProcessor;                                       //0x218
        struct
        {
            ULONG NextProcessorNumber : 31;                                   //0x218
            ULONG SharedReadyQueue : 1;                                       //0x218
        };
    };
    LONG QueuePriority;                                                     //0x21c
    struct _KPROCESS* Process;                                              //0x220
    struct _KAFFINITY_EX* UserAffinity;                                     //0x228
    USHORT UserAffinityPrimaryGroup;                                        //0x230
    CHAR PreviousMode;                                                      //0x232
    CHAR BasePriority;                                                      //0x233
    union
    {
        CHAR PriorityDecrement;                                             //0x234
        struct
        {
            UCHAR ForegroundBoost : 4;                                        //0x234
            UCHAR UnusualBoost : 4;                                           //0x234
        };
    };
    UCHAR Preempted;                                                        //0x235
    UCHAR AdjustReason;                                                     //0x236
    CHAR AdjustIncrement;                                                   //0x237
    ULONGLONG AffinityVersion;                                              //0x238
    struct _KAFFINITY_EX* Affinity;                                         //0x240
    USHORT AffinityPrimaryGroup;                                            //0x248
    UCHAR ApcStateIndex;                                                    //0x24a
    UCHAR WaitBlockCount;                                                   //0x24b
    ULONG IdealProcessor;                                                   //0x24c
    ULONGLONG NpxState;                                                     //0x250
    union
    {
        struct _KAPC_STATE SavedApcState;                                   //0x258
        struct
        {
            UCHAR SavedApcStateFill[43];                                    //0x258
            UCHAR WaitReason;                                               //0x283
            CHAR SuspendCount;                                              //0x284
            CHAR Saturation;                                                //0x285
            USHORT SListFaultCount;                                         //0x286
        };
    };
    union
    {
        struct _KAPC SchedulerApc;                                          //0x288
        struct
        {
            UCHAR SchedulerApcFill1[3];                                     //0x288
            UCHAR QuantumReset;                                             //0x28b
        };
        struct
        {
            UCHAR SchedulerApcFill2[4];                                     //0x288
            ULONG KernelTime;                                               //0x28c
        };
        struct
        {
            UCHAR SchedulerApcFill3[64];                                    //0x288
            struct _KPRCB* volatile WaitPrcb;                               //0x2c8
        };
        struct
        {
            UCHAR SchedulerApcFill4[72];                                    //0x288
            VOID* LegoData;                                                 //0x2d0
        };
        struct
        {
            UCHAR SchedulerApcFill5[83];                                    //0x288
            UCHAR CallbackNestingLevel;                                     //0x2db
            ULONG UserTime;                                                 //0x2dc
        };
    };
    struct _KEVENT SuspendEvent;                                            //0x2e0
    struct _LIST_ENTRY ThreadListEntry;                                     //0x2f8
    struct _LIST_ENTRY MutantListHead;                                      //0x308
    UCHAR AbEntrySummary;                                                   //0x318
    UCHAR AbWaitEntryCount;                                                 //0x319
    union
    {
        UCHAR FreezeFlags;                                                  //0x31a
        struct
        {
            UCHAR FreezeCount2 : 1;                                           //0x31a
            UCHAR FreezeNormal : 1;                                           //0x31a
            UCHAR FreezeDeep : 1;                                             //0x31a
        };
    };
    CHAR SystemPriority;                                                    //0x31b
    ULONG SecureThreadCookie;                                               //0x31c
    VOID* Spare22;                                                          //0x320
    struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x328
    struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x330
    UCHAR PriorityFloorCounts[32];                                          //0x338
    ULONG PriorityFloorSummary;                                             //0x358
    volatile LONG AbCompletedIoBoostCount;                                  //0x35c
    volatile LONG AbCompletedIoQoSBoostCount;                               //0x360
    volatile SHORT KeReferenceCount;                                        //0x364
    UCHAR AbOrphanedEntrySummary;                                           //0x366
    UCHAR AbOwnedEntryCount;                                                //0x367
    ULONG ForegroundLossTime;                                               //0x368
    union
    {
        struct _LIST_ENTRY GlobalForegroundListEntry;                       //0x370
        struct
        {
            struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x370
            ULONGLONG InGlobalForegroundList;                               //0x378
        };
    };
    LONGLONG ReadOperationCount;                                            //0x380
    LONGLONG WriteOperationCount;                                           //0x388
    LONGLONG OtherOperationCount;                                           //0x390
    LONGLONG ReadTransferCount;                                             //0x398
    LONGLONG WriteTransferCount;                                            //0x3a0
    LONGLONG OtherTransferCount;                                            //0x3a8
    struct _KSCB* QueuedScb;                                                //0x3b0
    volatile ULONG ThreadTimerDelay;                                        //0x3b8
    union
    {
        volatile LONG ThreadFlags3;                                         //0x3bc
        struct
        {
            ULONG ThreadFlags3Reserved : 8;                                   //0x3bc
            ULONG PpmPolicy : 3;                                              //0x3bc
            ULONG ThreadFlags3Reserved2 : 21;                                 //0x3bc
        };
    };
    ULONGLONG TracingPrivate[1];                                            //0x3c0
    VOID* SchedulerAssist;                                                  //0x3c8
    VOID* volatile AbWaitObject;                                            //0x3d0
    ULONG ReservedPreviousReadyTimeValue;                                   //0x3d8
    ULONGLONG KernelWaitTime;                                               //0x3e0
    ULONGLONG UserWaitTime;                                                 //0x3e8
    union
    {
        struct _LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry;           //0x3f0
        struct
        {
            struct _SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry; //0x3f0
            ULONGLONG InGlobalUpdateVpThreadPriorityList;                   //0x3f8
        };
    };
    LONG SchedulerAssistPriorityFloor;                                      //0x400
    LONG RealtimePriorityFloor;                                             //0x404
    VOID* KernelShadowStack;                                                //0x408
    VOID* KernelShadowStackInitial;                                         //0x410
    VOID* KernelShadowStackBase;                                            //0x418
    union _KERNEL_SHADOW_STACK_LIMIT KernelShadowStackLimit;                //0x420
    ULONGLONG ExtendedFeatureDisableMask;                                   //0x428
    ULONGLONG HgsFeedbackStartTime;                                         //0x430
    ULONGLONG HgsFeedbackCycles;                                            //0x438
    ULONG HgsInvalidFeedbackCount;                                          //0x440
    ULONG HgsLowerPerfClassFeedbackCount;                                   //0x444
    ULONG HgsHigherPerfClassFeedbackCount;                                  //0x448
    ULONG Spare27;                                                          //0x44c
    struct _SINGLE_LIST_ENTRY SystemAffinityTokenListHead;                  //0x450
    VOID* IptSaveArea;                                                      //0x458
    UCHAR ResourceIndex;                                                    //0x460
    UCHAR CoreIsolationReasons;                                             //0x461
    UCHAR BamQosLevelFromAssistPage;                                        //0x462
    UCHAR Spare31[1];                                                       //0x463
    ULONG Spare32;                                                          //0x464
    ULONGLONG EndPadding[3];                                                //0x468
};

//0x20 bytes (sizeof)
struct _KSEMAPHORE
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    LONG Limit;                                                             //0x18
};

//0x8 bytes (sizeof)
union _PS_CLIENT_SECURITY_CONTEXT
{
    ULONGLONG ImpersonationData;                                            //0x0
    VOID* ImpersonationToken;                                               //0x0
    ULONGLONG ImpersonationLevel : 2;                                         //0x0
    ULONGLONG EffectiveOnly : 1;                                              //0x0
};

//0x18 bytes (sizeof)
struct _PS_PROPERTY_SET
{
    struct _LIST_ENTRY ListHead;                                            //0x0
    ULONGLONG Lock;                                                         //0x10
};

//0x10 bytes (sizeof)
struct _RTL_RB_TREE
{
    struct _RTL_BALANCED_NODE* Root;                                        //0x0
    union
    {
        UCHAR Encoded : 1;                                                    //0x8
        struct _RTL_BALANCED_NODE* Min;                                     //0x8
    };
};

//0x10 bytes (sizeof)
struct _KLOCK_ENTRY_LOCK_STATE
{
    union
    {
        struct
        {
            ULONGLONG CrossThreadReleasable : 1;                              //0x0
            ULONGLONG Busy : 1;                                               //0x0
            ULONGLONG Reserved : 61;                                          //0x0
            ULONGLONG InTree : 1;                                             //0x0
        };
        VOID* LockState;                                                    //0x0
    };
    union
    {
        VOID* SessionState;                                                 //0x8
        struct
        {
            ULONG SessionId;                                                //0x8
            ULONG SessionPad;                                               //0xc
        };
    };
};

//0x8 bytes (sizeof)
union _KLOCK_ENTRY_BOOST_BITMAP
{
    ULONGLONG AllFields;                                                    //0x0
    struct
    {
        ULONG AllBoosts;                                                    //0x0
        ULONG WaiterCounts;                                                 //0x4
    };
    ULONG CpuBoostsBitmap : 30;                                               //0x0
    ULONG IoBoost : 1;                                                        //0x0
    struct
    {
        ULONG IoQoSBoost : 1;                                                 //0x0
        ULONG IoNormalPriorityWaiterCount : 8;                                    //0x4
    };
    ULONG IoQoSWaiterCount : 7;                                               //0x4
};

//0x60 bytes (sizeof)
struct _KLOCK_ENTRY
{
    union
    {
        struct _KLOCK_ENTRY_LOCK_STATE LockState;                           //0x0
        VOID* volatile LockUnsafe;                                          //0x0
        struct
        {
            volatile UCHAR CrossThreadReleasableAndBusyByte;                //0x0
            UCHAR Reserved[6];                                              //0x1
            volatile UCHAR InTreeByte;                                      //0x7
            union
            {
                VOID* SessionState;                                         //0x8
                struct
                {
                    ULONG SessionId;                                        //0x8
                    ULONG SessionPad;                                       //0xc
                };
            };
        };
    };
    union
    {
        ULONG EntryFlags;                                                   //0x10
        struct
        {
            UCHAR EntryIndex;                                               //0x10
            UCHAR WaitingByte;                                              //0x11
            UCHAR AcquiredByte;                                             //0x12
            union
            {
                UCHAR CrossThreadFlags;                                     //0x13
                struct
                {
                    UCHAR HeadNodeBit : 1;                                    //0x13
                    UCHAR IoPriorityBit : 1;                                  //0x13
                    UCHAR IoQoSWaiter : 1;                                    //0x13
                    UCHAR Spare1 : 5;                                         //0x13
                };
            };
        };
        struct
        {
            ULONG StaticState : 8;                                            //0x10
            ULONG AllFlags : 24;                                              //0x10
        };
    };
    ULONG SpareFlags;                                                       //0x14
    struct _RTL_BALANCED_NODE TreeNode;                                     //0x18
    union
    {
        struct
        {
            struct _RTL_RB_TREE OwnerTree;                                  //0x30
            struct _RTL_RB_TREE WaiterTree;                                 //0x40
        };
        CHAR CpuPriorityKey;                                                //0x30
    };
    ULONGLONG EntryLock;                                                    //0x50
    union _KLOCK_ENTRY_BOOST_BITMAP BoostBitmap;                            //0x58
};

//0x900 bytes (sizeof)
struct _ETHREAD
{
    struct _KTHREAD Tcb;                                                    //0x0
    union _LARGE_INTEGER CreateTime;                                        //0x480
    union
    {
        union _LARGE_INTEGER ExitTime;                                      //0x488
        struct _LIST_ENTRY KeyedWaitChain;                                  //0x488
    };
    union
    {
        struct _LIST_ENTRY PostBlockList;                                   //0x498
        struct
        {
            VOID* ForwardLinkShadow;                                        //0x498
            VOID* StartAddress;                                             //0x4a0
        };
    };
    union
    {
        struct _TERMINATION_PORT* TerminationPort;                          //0x4a8
        struct _ETHREAD* ReaperLink;                                        //0x4a8
        VOID* KeyedWaitValue;                                               //0x4a8
    };
    ULONGLONG ActiveTimerListLock;                                          //0x4b0
    struct _LIST_ENTRY ActiveTimerListHead;                                 //0x4b8
    struct _CLIENT_ID Cid;                                                  //0x4c8
    union
    {
        struct _KSEMAPHORE KeyedWaitSemaphore;                              //0x4d8
        struct _KSEMAPHORE AlpcWaitSemaphore;                               //0x4d8
    };
    union _PS_CLIENT_SECURITY_CONTEXT ClientSecurity;                       //0x4f8
    struct _LIST_ENTRY IrpList;                                             //0x500
    ULONGLONG TopLevelIrp;                                                  //0x510
    struct _DEVICE_OBJECT* DeviceToVerify;                                  //0x518
    VOID* Win32StartAddress;                                                //0x520
    VOID* ChargeOnlySession;                                                //0x528
    VOID* LegacyPowerObject;                                                //0x530
    struct _LIST_ENTRY ThreadListEntry;                                     //0x538
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x548
    struct _EX_PUSH_LOCK ThreadLock;                                        //0x550
    ULONG ReadClusterSize;                                                  //0x558
    volatile LONG MmLockOrdering;                                           //0x55c
    union
    {
        ULONG CrossThreadFlags;                                             //0x560
        struct
        {
            ULONG Terminated : 1;                                             //0x560
            ULONG ThreadInserted : 1;                                         //0x560
            ULONG HideFromDebugger : 1;                                       //0x560
            ULONG ActiveImpersonationInfo : 1;                                //0x560
            ULONG HardErrorsAreDisabled : 1;                                  //0x560
            ULONG BreakOnTermination : 1;                                     //0x560
            ULONG SkipCreationMsg : 1;                                        //0x560
            ULONG SkipTerminationMsg : 1;                                     //0x560
            ULONG CopyTokenOnOpen : 1;                                        //0x560
            ULONG ThreadIoPriority : 3;                                       //0x560
            ULONG ThreadPagePriority : 3;                                     //0x560
            ULONG RundownFail : 1;                                            //0x560
            ULONG UmsForceQueueTermination : 1;                               //0x560
            ULONG IndirectCpuSets : 1;                                        //0x560
            ULONG DisableDynamicCodeOptOut : 1;                               //0x560
            ULONG ExplicitCaseSensitivity : 1;                                //0x560
            ULONG PicoNotifyExit : 1;                                         //0x560
            ULONG DbgWerUserReportActive : 1;                                 //0x560
            ULONG ForcedSelfTrimActive : 1;                                   //0x560
            ULONG SamplingCoverage : 1;                                       //0x560
            ULONG ReservedCrossThreadFlags : 8;                               //0x560
        };
    };
    union
    {
        ULONG SameThreadPassiveFlags;                                       //0x564
        struct
        {
            ULONG ActiveExWorker : 1;                                         //0x564
            ULONG MemoryMaker : 1;                                            //0x564
            ULONG StoreLockThread : 2;                                        //0x564
            ULONG ClonedThread : 1;                                           //0x564
            ULONG KeyedEventInUse : 1;                                        //0x564
            ULONG SelfTerminate : 1;                                          //0x564
            ULONG RespectIoPriority : 1;                                      //0x564
            ULONG ActivePageLists : 1;                                        //0x564
            ULONG SecureContext : 1;                                          //0x564
            ULONG ZeroPageThread : 1;                                         //0x564
            ULONG WorkloadClass : 1;                                          //0x564
            ULONG GenerateDumpOnBadHandleAccess : 1;                          //0x564
            ULONG ReservedSameThreadPassiveFlags : 19;                        //0x564
        };
    };
    union
    {
        ULONG SameThreadApcFlags;                                           //0x568
        struct
        {
            UCHAR OwnsProcessAddressSpaceExclusive : 1;                       //0x568
            UCHAR OwnsProcessAddressSpaceShared : 1;                          //0x568
            UCHAR HardFaultBehavior : 1;                                      //0x568
            volatile UCHAR StartAddressInvalid : 1;                           //0x568
            UCHAR EtwCalloutActive : 1;                                       //0x568
            UCHAR SuppressSymbolLoad : 1;                                     //0x568
            UCHAR Prefetching : 1;                                            //0x568
            UCHAR OwnsVadExclusive : 1;                                       //0x568
            UCHAR SystemPagePriorityActive : 1;                               //0x569
            UCHAR SystemPagePriority : 3;                                     //0x569
            UCHAR AllowUserWritesToExecutableMemory : 1;                      //0x569
            UCHAR AllowKernelWritesToExecutableMemory : 1;                    //0x569
            UCHAR OwnsVadShared : 1;                                          //0x569
            UCHAR SessionAttachActive : 1;                                    //0x569
            UCHAR PasidMsrValid : 1;                                          //0x56a
        };
    };
    UCHAR CacheManagerActive;                                               //0x56c
    UCHAR DisablePageFaultClustering;                                       //0x56d
    UCHAR ActiveFaultCount;                                                 //0x56e
    UCHAR LockOrderState;                                                   //0x56f
    ULONG PerformanceCountLowReserved;                                      //0x570
    LONG PerformanceCountHighReserved;                                      //0x574
    ULONGLONG AlpcMessageId;                                                //0x578
    union
    {
        VOID* AlpcMessage;                                                  //0x580
        ULONG AlpcReceiveAttributeSet;                                      //0x580
    };
    struct _LIST_ENTRY AlpcWaitListEntry;                                   //0x588
    LONG ExitStatus;                                                        //0x598
    ULONG CacheManagerCount;                                                //0x59c
    ULONG IoBoostCount;                                                     //0x5a0
    ULONG IoQoSBoostCount;                                                  //0x5a4
    ULONG IoQoSThrottleCount;                                               //0x5a8
    ULONG KernelStackReference;                                             //0x5ac
    struct _LIST_ENTRY BoostList;                                           //0x5b0
    struct _LIST_ENTRY DeboostList;                                         //0x5c0
    ULONGLONG BoostListLock;                                                //0x5d0
    ULONGLONG IrpListLock;                                                  //0x5d8
    VOID* ReservedForSynchTracking;                                         //0x5e0
    struct _SINGLE_LIST_ENTRY CmCallbackListHead;                           //0x5e8
    struct _GUID* ActivityId;                                               //0x5f0
    struct _SINGLE_LIST_ENTRY SeLearningModeListHead;                       //0x5f8
    VOID* VerifierContext;                                                  //0x600
    VOID* AdjustedClientToken;                                              //0x608
    VOID* WorkOnBehalfThread;                                               //0x610
    struct _PS_PROPERTY_SET PropertySet;                                    //0x618
    VOID* PicoContext;                                                      //0x630
    ULONGLONG UserFsBase;                                                   //0x638
    ULONGLONG UserGsBase;                                                   //0x640
    struct _THREAD_ENERGY_VALUES* EnergyValues;                             //0x648
    union
    {
        ULONGLONG SelectedCpuSets;                                          //0x650
        ULONGLONG* SelectedCpuSetsIndirect;                                 //0x650
    };
    struct _EJOB* Silo;                                                     //0x658
    struct _UNICODE_STRING* ThreadName;                                     //0x660
    struct _CONTEXT* SetContextState;                                       //0x668
    UCHAR LastSoftParkElectionQos;                                          //0x670
    UCHAR LastSoftParkElectionWorkloadType;                                 //0x671
    UCHAR LastSoftParkElectionRunningType;                                  //0x672
    UCHAR Spare1;                                                           //0x673
    ULONG HeapData;                                                         //0x674
    struct _LIST_ENTRY OwnerEntryListHead;                                  //0x678
    ULONGLONG DisownedOwnerEntryListLock;                                   //0x688
    struct _LIST_ENTRY DisownedOwnerEntryListHead;                          //0x690
    struct _KLOCK_ENTRY LockEntries[6];                                     //0x6a0
    VOID* CmThreadInfo;                                                     //0x8e0
    VOID* FlsData;                                                          //0x8e8
    ULONG LastExpectedRunTime;                                              //0x8f0
    ULONG LastSoftParkElectionRunTime;                                      //0x8f4
    ULONGLONG LastSoftParkElectionGeneration;                               //0x8f8
};

struct _PHYSICAL_MEMORY_RANGE
{
    ULONGLONG BaseAddress;
    LARGE_INTEGER NumberOfBytes;
};

typedef void (*POB_PRE_OPERATION_CALLBACK)(PVOID, PVOID);
typedef void (*POB_POST_OPERATION_CALLBACK)(PVOID, PVOID);

typedef ULONG OB_OPERATION;

struct _OB_OPERATION_REGISTRATION
{
    PVOID*                      ObjectType;                                 //0x0
    OB_OPERATION                Operations;                                 //0x8
    POB_PRE_OPERATION_CALLBACK  PreOperation;                               //0x10
    POB_POST_OPERATION_CALLBACK PostOperation;                              //0x18
};

struct _OB_CALLBACK_REGISTRATION
{
    USHORT                          Version;                                //0x0
    USHORT                          OperationRegistrationCount;             //0x2
    UNICODE_STRING                  Altitude;                               //0x8
    PVOID                           RegistrationContext;                    //0x18
    _OB_OPERATION_REGISTRATION*     OperationRegistration;                  //0x20
};

struct _ANSI_STRING
{
    USHORT Length;                                                           //0x0
    USHORT MaximumLength;                                                   //0x2
    PCHAR  Buffer;                                                          //0x8
};

//0x78 bytes (sizeof)
struct _OBJECT_TYPE_INITIALIZER
{
    UCHAR padding[0x78];
};

//0xd8 bytes (sizeof)
struct _OBJECT_TYPE
{
    struct _LIST_ENTRY TypeList;                                             //0x0
    struct _UNICODE_STRING Name;                                            //0x10
    VOID* DefaultObject;                                                    //0x20
    UCHAR Index;                                                            //0x28
    ULONG TotalNumberOfObjects;                                             //0x2c
    ULONG TotalNumberOfHandles;                                             //0x30
    ULONG HighWaterNumberOfObjects;                                         //0x34
    ULONG HighWaterNumberOfHandles;                                         //0x38
    UCHAR padding[4];                                                       //0x3c
    struct _OBJECT_TYPE_INITIALIZER TypeInfo;                               //0x40
    ULONGLONG TypeLock;                                                     //0xb8
    ULONG Key;                                                              //0xc0
    UCHAR padding2[4];                                                      //0xc4
    struct _LIST_ENTRY CallbackList;                                        //0xc8
};

//0x38 bytes (sizeof)
struct _FAST_MUTEX
{
    LONG Count;                                                             //0x0
    VOID* Owner;                                                            //0x8
    ULONG Contention;                                                       //0x10
    struct _KEVENT Event;                                                   //0x18
    ULONG OldIrql;                                                          //0x30
};
