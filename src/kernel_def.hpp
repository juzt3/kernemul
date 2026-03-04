#pragma once
#include <Windows.h>
#include <winternl.h>

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
