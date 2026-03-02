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

//0x120 bytes (sizeof)
struct _NT_LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary : 1;                                         //0x68
            ULONG MarkedForRemoval : 1;                                       //0x68
            ULONG ImageDll : 1;                                               //0x68
            ULONG LoadNotificationsSent : 1;                                  //0x68
            ULONG TelemetryEntryProcessed : 1;                                //0x68
            ULONG ProcessStaticImport : 1;                                    //0x68
            ULONG InLegacyLists : 1;                                          //0x68
            ULONG InIndexes : 1;                                              //0x68
            ULONG ShimDll : 1;                                                //0x68
            ULONG InExceptionTable : 1;                                       //0x68
            ULONG ReservedFlags1 : 2;                                         //0x68
            ULONG LoadInProgress : 1;                                         //0x68
            ULONG LoadConfigProcessed : 1;                                    //0x68
            ULONG EntryProcessed : 1;                                         //0x68
            ULONG ProtectDelayLoad : 1;                                       //0x68
            ULONG ReservedFlags3 : 2;                                         //0x68
            ULONG DontCallForThreads : 1;                                     //0x68
            ULONG ProcessAttachCalled : 1;                                    //0x68
            ULONG ProcessAttachFailed : 1;                                    //0x68
            ULONG CorDeferredValidate : 1;                                    //0x68
            ULONG CorImage : 1;                                               //0x68
            ULONG DontRelocate : 1;                                           //0x68
            ULONG CorILOnly : 1;                                              //0x68
            ULONG ChpeImage : 1;                                              //0x68
            ULONG ReservedFlags5 : 2;                                         //0x68
            ULONG Redirected : 1;                                             //0x68
            ULONG ReservedFlags6 : 2;                                         //0x68
            ULONG CompatDatabaseProcessed : 1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
};
