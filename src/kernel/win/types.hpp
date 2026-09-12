#pragma once
#include <cstdint>
#include <cstddef>

// MSVC uses __int64 as a built-in type; GCC/Clang need it defined
#ifndef _MSC_VER
#define __int64 long long
#pragma ms_struct on
#endif

// ntdiff Win11 24H2 (build 26100) x64 ntoskrnl types
// Source: https://ntdiff.github.io/

typedef struct _LIST_ENTRY
{
  /* 0x0000 */ struct _LIST_ENTRY* Flink;
  /* 0x0008 */ struct _LIST_ENTRY* Blink;
} LIST_ENTRY, *PLIST_ENTRY; /* size: 0x0010 */

typedef struct _UNICODE_STRING
{
  /* 0x0000 */ unsigned short Length;
  /* 0x0002 */ unsigned short MaximumLength;
  /* 0x0008 */ wchar_t* Buffer;
} UNICODE_STRING, *PUNICODE_STRING; /* size: 0x0010 */

typedef struct _DISPATCHER_HEADER
{
  union
  {
    /* 0x0000 */ volatile int Lock;
    /* 0x0000 */ int LockNV;
    struct
    {
      /* 0x0000 */ unsigned char Type;
      /* 0x0001 */ unsigned char Signalling;
      /* 0x0002 */ unsigned char Size;
      /* 0x0003 */ unsigned char Reserved1;
    }; /* size: 0x0004 */
    struct
    {
      /* 0x0000 */ unsigned char TimerType;
      union
      {
        /* 0x0001 */ unsigned char TimerControlFlags;
        struct
        {
          struct /* bitfield */
          {
            /* 0x0001 */ unsigned char Absolute : 1; /* bit position: 0 */
            /* 0x0001 */ unsigned char Wake : 1; /* bit position: 1 */
            /* 0x0001 */ unsigned char EncodedTolerableDelay : 6; /* bit position: 2 */
          }; /* bitfield */
          /* 0x0002 */ unsigned char Hand;
          union
          {
            /* 0x0003 */ unsigned char TimerMiscFlags;
            struct /* bitfield */
            {
              /* 0x0003 */ unsigned char Index : 6; /* bit position: 0 */
              /* 0x0003 */ unsigned char Inserted : 1; /* bit position: 6 */
              /* 0x0003 */ volatile unsigned char Expired : 1; /* bit position: 7 */
            }; /* bitfield */
          }; /* size: 0x0001 */
        }; /* size: 0x0003 */
      }; /* size: 0x0003 */
    }; /* size: 0x0004 */
    struct
    {
      /* 0x0000 */ unsigned char Timer2Type;
      union
      {
        /* 0x0001 */ unsigned char Timer2Flags;
        struct
        {
          struct /* bitfield */
          {
            /* 0x0001 */ unsigned char Timer2Inserted : 1; /* bit position: 0 */
            /* 0x0001 */ unsigned char Timer2Expiring : 1; /* bit position: 1 */
            /* 0x0001 */ unsigned char Timer2CancelPending : 1; /* bit position: 2 */
            /* 0x0001 */ unsigned char Timer2SetPending : 1; /* bit position: 3 */
            /* 0x0001 */ unsigned char Timer2Running : 1; /* bit position: 4 */
            /* 0x0001 */ unsigned char Timer2Disabled : 1; /* bit position: 5 */
            /* 0x0001 */ unsigned char Timer2ReservedFlags : 2; /* bit position: 6 */
          }; /* bitfield */
          /* 0x0002 */ unsigned char Timer2ComponentId;
          /* 0x0003 */ unsigned char Timer2RelativeId;
        }; /* size: 0x0003 */
      }; /* size: 0x0003 */
    }; /* size: 0x0004 */
    struct
    {
      /* 0x0000 */ unsigned char QueueType;
      union
      {
        /* 0x0001 */ unsigned char QueueControlFlags;
        struct
        {
          struct /* bitfield */
          {
            /* 0x0001 */ unsigned char Abandoned : 1; /* bit position: 0 */
            /* 0x0001 */ unsigned char DisableIncrement : 1; /* bit position: 1 */
            /* 0x0001 */ unsigned char QueueReservedControlFlags : 6; /* bit position: 2 */
          }; /* bitfield */
          /* 0x0002 */ unsigned char QueueSize;
          /* 0x0003 */ unsigned char QueueReserved;
        }; /* size: 0x0003 */
      }; /* size: 0x0003 */
    }; /* size: 0x0004 */
    struct
    {
      /* 0x0000 */ unsigned char ThreadType;
      /* 0x0001 */ unsigned char ThreadReserved;
      union
      {
        /* 0x0002 */ unsigned char ThreadControlFlags;
        struct
        {
          struct /* bitfield */
          {
            /* 0x0002 */ unsigned char CycleProfiling : 1; /* bit position: 0 */
            /* 0x0002 */ unsigned char CounterProfiling : 1; /* bit position: 1 */
            /* 0x0002 */ unsigned char GroupScheduling : 1; /* bit position: 2 */
            /* 0x0002 */ unsigned char AffinitySet : 1; /* bit position: 3 */
            /* 0x0002 */ unsigned char Tagged : 1; /* bit position: 4 */
            /* 0x0002 */ unsigned char EnergyProfiling : 1; /* bit position: 5 */
            /* 0x0002 */ unsigned char SchedulerAssist : 1; /* bit position: 6 */
            /* 0x0002 */ unsigned char ThreadReservedControlFlags : 1; /* bit position: 7 */
          }; /* bitfield */
          union
          {
            /* 0x0003 */ unsigned char DebugActive;
            struct /* bitfield */
            {
              /* 0x0003 */ unsigned char ActiveDR7 : 1; /* bit position: 0 */
              /* 0x0003 */ unsigned char Instrumented : 1; /* bit position: 1 */
              /* 0x0003 */ unsigned char Minimal : 1; /* bit position: 2 */
              /* 0x0003 */ unsigned char Reserved4 : 2; /* bit position: 3 */
              /* 0x0003 */ unsigned char AltSyscall : 1; /* bit position: 5 */
              /* 0x0003 */ unsigned char Emulation : 1; /* bit position: 6 */
              /* 0x0003 */ unsigned char Reserved5 : 1; /* bit position: 7 */
            }; /* bitfield */
          }; /* size: 0x0001 */
        }; /* size: 0x0002 */
      }; /* size: 0x0002 */
    }; /* size: 0x0004 */
    struct
    {
      /* 0x0000 */ unsigned char MutantType;
      /* 0x0001 */ unsigned char MutantSize;
      /* 0x0002 */ unsigned char DpcActive;
      /* 0x0003 */ unsigned char MutantReserved;
    }; /* size: 0x0004 */
  }; /* size: 0x0004 */
  /* 0x0004 */ int SignalState;
  /* 0x0008 */ struct _LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, *PDISPATCHER_HEADER; /* size: 0x0018 */

typedef struct _KAB_UM_PROCESS_CONTEXT
{
  /* 0x0000 */ struct _KAB_UM_PROCESS_TREE* Trees;
  /* 0x0008 */ unsigned int TreeCount;
  /* 0x000c */ int __PADDING__[1];
} KAB_UM_PROCESS_CONTEXT, *PKAB_UM_PROCESS_CONTEXT; /* size: 0x0010 */

typedef struct _SINGLE_LIST_ENTRY
{
  /* 0x0000 */ struct _SINGLE_LIST_ENTRY* Next;
} SINGLE_LIST_ENTRY, *PSINGLE_LIST_ENTRY; /* size: 0x0008 */

typedef union _KEXECUTE_OPTIONS
{
  union
  {
    struct /* bitfield */
    {
      /* 0x0000 */ unsigned char ExecuteDisable : 1; /* bit position: 0 */
      /* 0x0000 */ unsigned char ExecuteEnable : 1; /* bit position: 1 */
      /* 0x0000 */ unsigned char DisableThunkEmulation : 1; /* bit position: 2 */
      /* 0x0000 */ unsigned char Permanent : 1; /* bit position: 3 */
      /* 0x0000 */ unsigned char ExecuteDispatchEnable : 1; /* bit position: 4 */
      /* 0x0000 */ unsigned char ImageDispatchEnable : 1; /* bit position: 5 */
      /* 0x0000 */ unsigned char DisableExceptionChainValidation : 1; /* bit position: 6 */
      /* 0x0000 */ unsigned char Spare : 1; /* bit position: 7 */
    }; /* bitfield */
    /* 0x0000 */ volatile unsigned char ExecuteOptions;
    /* 0x0000 */ unsigned char ExecuteOptionsNV;
  }; /* size: 0x0001 */
} KEXECUTE_OPTIONS, *PKEXECUTE_OPTIONS; /* size: 0x0001 */

typedef struct _KGROUP_MASK
{
  /* 0x0000 */ unsigned __int64 Masks[2];
} KGROUP_MASK, *PKGROUP_MASK; /* size: 0x0010 */

typedef union _KSTACK_COUNT
{
  union
  {
    /* 0x0000 */ int Value;
    struct /* bitfield */
    {
      /* 0x0000 */ unsigned int State : 3; /* bit position: 0 */
      /* 0x0000 */ unsigned int StackCount : 29; /* bit position: 3 */
    }; /* bitfield */
  }; /* size: 0x0004 */
} KSTACK_COUNT, *PKSTACK_COUNT; /* size: 0x0004 */

typedef struct _KPROCESS
{
  /* 0x0000 */ struct _DISPATCHER_HEADER Header;
  /* 0x0018 */ struct _LIST_ENTRY ProfileListHead;
  /* 0x0028 */ unsigned __int64 DirectoryTableBase;
  /* 0x0030 */ struct _LIST_ENTRY ThreadListHead;
  /* 0x0040 */ unsigned int ProcessLock;
  /* 0x0044 */ unsigned int ProcessTimerDelay;
  /* 0x0048 */ unsigned __int64 DeepFreezeStartTime;
  /* 0x0050 */ struct _KAFFINITY_EX* Affinity;
  /* 0x0058 */ struct _KAB_UM_PROCESS_CONTEXT AutoBoostState;
  /* 0x0068 */ struct _LIST_ENTRY ReadyListHead;
  /* 0x0078 */ struct _SINGLE_LIST_ENTRY SwapListEntry;
  /* 0x0080 */ volatile struct _KAFFINITY_EX* ActiveProcessors;
  union
  {
    struct /* bitfield */
    {
      /* 0x0088 */ unsigned int AutoAlignment : 1; /* bit position: 0 */
      /* 0x0088 */ unsigned int DisableBoost : 1; /* bit position: 1 */
      /* 0x0088 */ unsigned int DisableQuantum : 1; /* bit position: 2 */
      /* 0x0088 */ unsigned int DeepFreeze : 1; /* bit position: 3 */
      /* 0x0088 */ unsigned int TimerVirtualization : 1; /* bit position: 4 */
      /* 0x0088 */ unsigned int CheckStackExtents : 1; /* bit position: 5 */
      /* 0x0088 */ unsigned int CacheIsolationEnabled : 1; /* bit position: 6 */
      /* 0x0088 */ unsigned int PpmPolicy : 4; /* bit position: 7 */
      /* 0x0088 */ unsigned int VaSpaceDeleted : 1; /* bit position: 11 */
      /* 0x0088 */ unsigned int MultiGroup : 1; /* bit position: 12 */
      /* 0x0088 */ unsigned int ForegroundProcess : 1; /* bit position: 13 */
      /* 0x0088 */ unsigned int ReservedFlags : 18; /* bit position: 14 */
    }; /* bitfield */
    /* 0x0088 */ volatile int ProcessFlags;
  }; /* size: 0x0004 */
  /* 0x008c */ unsigned int Spare0c;
  /* 0x0090 */ char BasePriority;
  /* 0x0091 */ char QuantumReset;
  /* 0x0092 */ char Visited;
  /* 0x0093 */ union _KEXECUTE_OPTIONS Flags;
  /* 0x0098 */ struct _KGROUP_MASK ActiveGroupsMask;
  /* 0x00a8 */ unsigned __int64 ActiveGroupPadding[2];
  /* 0x00b8 */ struct _KI_IDEAL_PROCESSOR_ASSIGNMENT_BLOCK* IdealProcessorAssignmentBlock;
  /* 0x00c0 */ unsigned __int64 Padding[8];
  /* 0x0100 */ unsigned int Spare0d;
  /* 0x0104 */ unsigned short IdealGlobalNode;
  /* 0x0106 */ unsigned short Spare1;
  /* 0x0108 */ volatile union _KSTACK_COUNT StackCount;
  /* 0x0110 */ struct _LIST_ENTRY ProcessListEntry;
  /* 0x0120 */ unsigned __int64 CycleTime;
  /* 0x0128 */ unsigned __int64 ContextSwitches;
  /* 0x0130 */ struct _KSCHEDULING_GROUP* SchedulingGroup;
  /* 0x0138 */ unsigned __int64 KernelTime;
  /* 0x0140 */ unsigned __int64 UserTime;
  /* 0x0148 */ unsigned __int64 ReadyTime;
  /* 0x0150 */ unsigned int FreezeCount;
  /* 0x0154 */ unsigned int Spare4;
  /* 0x0158 */ unsigned __int64 UserDirectoryTableBase;
  /* 0x0160 */ unsigned char AddressPolicy;
  /* 0x0161 */ unsigned char Spare2[7];
  /* 0x0168 */ void* InstrumentationCallback;
  union
  {
    union
    {
      /* 0x0170 */ unsigned __int64 SecureHandle;
      struct
      {
        struct /* bitfield */
        {
          /* 0x0170 */ unsigned __int64 SecureProcess : 1; /* bit position: 0 */
          /* 0x0170 */ unsigned __int64 TrustedApp : 1; /* bit position: 1 */
        }; /* bitfield */
      } /* size: 0x0008 */ Flags;
    }; /* size: 0x0008 */
  } /* size: 0x0008 */ SecureState;
  /* 0x0178 */ unsigned __int64 KernelWaitTime;
  /* 0x0180 */ unsigned __int64 UserWaitTime;
  /* 0x0188 */ unsigned __int64 LastRebalanceQpc;
  /* 0x0190 */ void* PerProcessorCycleTimes;
  /* 0x0198 */ unsigned __int64 ExtendedFeatureDisableMask;
  /* 0x01a0 */ unsigned short PrimaryGroup;
  /* 0x01a2 */ unsigned short Spare3[3];
  /* 0x01a8 */ void* UserCetLogging;
  /* 0x01b0 */ struct _LIST_ENTRY CpuPartitionList;
  /* 0x01c0 */ struct _KPROCESS_AVAILABLE_CPU_STATE* AvailableCpuState;
} KPROCESS, *PKPROCESS; /* size: 0x01c8 */

typedef struct _EX_PUSH_LOCK
{
  union
  {
    struct /* bitfield */
    {
      /* 0x0000 */ unsigned __int64 Locked : 1; /* bit position: 0 */
      /* 0x0000 */ unsigned __int64 Waiting : 1; /* bit position: 1 */
      /* 0x0000 */ unsigned __int64 Waking : 1; /* bit position: 2 */
      /* 0x0000 */ unsigned __int64 MultipleShared : 1; /* bit position: 3 */
      /* 0x0000 */ unsigned __int64 Shared : 60; /* bit position: 4 */
    }; /* bitfield */
    /* 0x0000 */ unsigned __int64 Value;
    /* 0x0000 */ void* Ptr;
  }; /* size: 0x0008 */
} EX_PUSH_LOCK, *PEX_PUSH_LOCK; /* size: 0x0008 */

typedef struct _EX_RUNDOWN_REF
{
  union
  {
    /* 0x0000 */ unsigned __int64 Count;
    /* 0x0000 */ void* Ptr;
  }; /* size: 0x0008 */
} EX_RUNDOWN_REF, *PEX_RUNDOWN_REF; /* size: 0x0008 */

typedef union _LARGE_INTEGER
{
  union
  {
    struct
    {
      /* 0x0000 */ unsigned int LowPart;
      /* 0x0004 */ int HighPart;
    }; /* size: 0x0008 */
    struct
    {
      /* 0x0000 */ unsigned int LowPart;
      /* 0x0004 */ int HighPart;
    } /* size: 0x0008 */ u;
    /* 0x0000 */ __int64 QuadPart;
  }; /* size: 0x0008 */
} LARGE_INTEGER, *PLARGE_INTEGER; /* size: 0x0008 */

typedef struct _EX_FAST_REF
{
  union
  {
    /* 0x0000 */ void* Object;
    /* 0x0000 */ unsigned __int64 RefCnt : 4; /* bit position: 0 */
    /* 0x0000 */ unsigned __int64 Value;
  }; /* size: 0x0008 */
} EX_FAST_REF, *PEX_FAST_REF; /* size: 0x0008 */

typedef struct _RTL_AVL_TREE
{
  /* 0x0000 */ struct _RTL_BALANCED_NODE* Root;
} RTL_AVL_TREE, *PRTL_AVL_TREE; /* size: 0x0008 */

typedef struct _SE_AUDIT_PROCESS_CREATION_INFO
{
  /* 0x0000 */ struct _OBJECT_NAME_INFORMATION* ImageFileName;
} SE_AUDIT_PROCESS_CREATION_INFO, *PSE_AUDIT_PROCESS_CREATION_INFO; /* size: 0x0008 */

typedef struct _MMSUPPORT_FLAGS
{
  union
  {
    struct
    {
      struct /* bitfield */
      {
        /* 0x0000 */ unsigned char WorkingSetType : 4; /* bit position: 0 */
        /* 0x0000 */ unsigned char Reserved0 : 2; /* bit position: 4 */
        /* 0x0000 */ unsigned char MaximumWorkingSetHard : 1; /* bit position: 6 */
        /* 0x0000 */ unsigned char MinimumWorkingSetHard : 1; /* bit position: 7 */
      }; /* bitfield */
      struct /* bitfield */
      {
        /* 0x0001 */ unsigned char Reserved1 : 1; /* bit position: 0 */
        /* 0x0001 */ unsigned char TrimmerState : 2; /* bit position: 1 */
        /* 0x0001 */ unsigned char LinearAddressProtected : 1; /* bit position: 3 */
        /* 0x0001 */ unsigned char PageStealers : 4; /* bit position: 4 */
      }; /* bitfield */
    }; /* size: 0x0002 */
    struct
    {
      /* 0x0000 */ unsigned short u1;
      /* 0x0002 */ unsigned char MemoryPriority;
      union
      {
        struct /* bitfield */
        {
          /* 0x0003 */ unsigned char WsleDeleted : 1; /* bit position: 0 */
          /* 0x0003 */ unsigned char SvmEnabled : 1; /* bit position: 1 */
          /* 0x0003 */ unsigned char ForceAge : 1; /* bit position: 2 */
          /* 0x0003 */ unsigned char ForceTrim : 1; /* bit position: 3 */
          /* 0x0003 */ unsigned char CommitReleaseState : 2; /* bit position: 4 */
          /* 0x0003 */ unsigned char Reserved2 : 2; /* bit position: 6 */
        }; /* bitfield */
        /* 0x0003 */ unsigned char u2;
      }; /* size: 0x0001 */
    }; /* size: 0x0004 */
    /* 0x0000 */ unsigned int EntireFlags;
  }; /* size: 0x0004 */
} MMSUPPORT_FLAGS, *PMMSUPPORT_FLAGS; /* size: 0x0004 */

typedef struct _MMSUPPORT_INSTANCE
{
  /* 0x0000 */ unsigned int NextPageColor;
  /* 0x0004 */ volatile unsigned int PageFaultCount;
  /* 0x0008 */ unsigned __int64 TrimmedPageCount;
  /* 0x0010 */ struct _MMWSL_INSTANCE* VmWorkingSetList;
  /* 0x0018 */ struct _LIST_ENTRY WorkingSetExpansionLinks;
  /* 0x0028 */ volatile unsigned __int64 AgeDistribution[8];
  /* 0x0068 */ struct _KGATE* ExitOutswapGate;
  /* 0x0070 */ unsigned __int64 MinimumWorkingSetSize;
  /* 0x0078 */ unsigned __int64 MaximumWorkingSetSize;
  /* 0x0080 */ volatile unsigned __int64 WorkingSetLeafSize;
  /* 0x0088 */ volatile unsigned __int64 WorkingSetLeafPrivateSize;
  /* 0x0090 */ volatile unsigned __int64 WorkingSetSize;
  /* 0x0098 */ volatile unsigned __int64 WorkingSetPrivateSize;
  /* 0x00a0 */ volatile unsigned __int64 PeakWorkingSetSize;
  /* 0x00a8 */ unsigned int HardFaultCount;
  /* 0x00ac */ unsigned short LastTrimStamp;
  /* 0x00ae */ unsigned short PartitionId;
  /* 0x00b0 */ unsigned __int64 SelfmapLock;
  /* 0x00b8 */ volatile struct _MMSUPPORT_FLAGS Flags;
  /* 0x00bc */ volatile unsigned int InterlockedFlags;
} MMSUPPORT_INSTANCE, *PMMSUPPORT_INSTANCE; /* size: 0x00c0 */

typedef struct _MMSUPPORT_SHARED
{
  /* 0x0000 */ void* WorkingSetLockArray;
  /* 0x0008 */ unsigned __int64 ReleasedCommitDebt;
  /* 0x0010 */ unsigned __int64 ResetPagesRepurposedCount;
  /* 0x0018 */ void* WsSwapSupport;
  /* 0x0020 */ void* CommitReleaseContext;
  /* 0x0028 */ void* AccessLog;
  /* 0x0030 */ volatile unsigned __int64 ChargedWslePages;
  /* 0x0038 */ volatile unsigned __int64 ActualWslePages;
  /* 0x0040 */ volatile int WorkingSetCoreLock;
  /* 0x0048 */ void* ShadowMapping;
  /* 0x0050 */ int __PADDING__[12];
} MMSUPPORT_SHARED, *PMMSUPPORT_SHARED; /* size: 0x0080 */

typedef struct _MMSUPPORT_FULL
{
  /* 0x0000 */ struct _MMSUPPORT_INSTANCE Instance;
  /* 0x00c0 */ struct _MMSUPPORT_SHARED Shared;
} MMSUPPORT_FULL, *PMMSUPPORT_FULL; /* size: 0x0140 */

typedef struct _ALPC_PROCESS_CONTEXT
{
  /* 0x0000 */ struct _EX_PUSH_LOCK Lock;
  /* 0x0008 */ struct _LIST_ENTRY ViewListHead;
  /* 0x0018 */ volatile unsigned __int64 PagedPoolQuotaCache;
} ALPC_PROCESS_CONTEXT, *PALPC_PROCESS_CONTEXT; /* size: 0x0020 */

typedef struct _PS_PROTECTION
{
  union
  {
    /* 0x0000 */ unsigned char Level;
    struct /* bitfield */
    {
      /* 0x0000 */ unsigned char Type : 3; /* bit position: 0 */
      /* 0x0000 */ unsigned char Audit : 1; /* bit position: 3 */
      /* 0x0000 */ unsigned char Signer : 4; /* bit position: 4 */
    }; /* bitfield */
  }; /* size: 0x0001 */
} PS_PROTECTION, *PPS_PROTECTION; /* size: 0x0001 */

typedef union _PS_INTERLOCKED_TIMER_DELAY_VALUES
{
  union
  {
    struct /* bitfield */
    {
      /* 0x0000 */ unsigned __int64 DelayMs : 30; /* bit position: 0 */
      /* 0x0000 */ unsigned __int64 CoalescingWindowMs : 30; /* bit position: 30 */
      /* 0x0000 */ unsigned __int64 Reserved : 1; /* bit position: 60 */
      /* 0x0000 */ unsigned __int64 NewTimerWheel : 1; /* bit position: 61 */
      /* 0x0000 */ unsigned __int64 Retry : 1; /* bit position: 62 */
      /* 0x0000 */ unsigned __int64 Locked : 1; /* bit position: 63 */
    }; /* bitfield */
    /* 0x0000 */ unsigned __int64 All;
  }; /* size: 0x0008 */
} PS_INTERLOCKED_TIMER_DELAY_VALUES, *PPS_INTERLOCKED_TIMER_DELAY_VALUES; /* size: 0x0008 */

typedef struct _WNF_STATE_NAME
{
  /* 0x0000 */ unsigned int Data[2];
} WNF_STATE_NAME, *PWNF_STATE_NAME; /* size: 0x0008 */

typedef struct _JOBOBJECT_WAKE_FILTER
{
  /* 0x0000 */ unsigned int HighEdgeFilter;
  /* 0x0004 */ unsigned int LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, *PJOBOBJECT_WAKE_FILTER; /* size: 0x0008 */

typedef struct _PS_PROCESS_WAKE_INFORMATION
{
  /* 0x0000 */ unsigned __int64 NotificationChannel;
  /* 0x0008 */ unsigned int WakeCounters[7];
  /* 0x0024 */ struct _JOBOBJECT_WAKE_FILTER WakeFilter;
  /* 0x002c */ unsigned int NoWakeCounter;
} PS_PROCESS_WAKE_INFORMATION, *PPS_PROCESS_WAKE_INFORMATION; /* size: 0x0030 */

typedef struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
{
  /* 0x0000 */ struct _RTL_AVL_TREE Tree;
  /* 0x0008 */ struct _EX_PUSH_LOCK Lock;
} PS_DYNAMIC_ENFORCED_ADDRESS_RANGES, *PPS_DYNAMIC_ENFORCED_ADDRESS_RANGES; /* size: 0x0010 */

typedef struct _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT
{
  /* 0x0000 */ unsigned int Level;
  /* 0x0004 */ unsigned int Slot;
} PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT, *PPSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT; /* size: 0x0008 */

typedef union _PROCESS_EXECUTION_TRANSITION
{
  union
  {
    /* 0x0000 */ volatile short TransitionState;
    struct /* bitfield */
    {
      /* 0x0000 */ unsigned short InProgress : 1; /* bit position: 0 */
      /* 0x0000 */ unsigned short Reserved : 7; /* bit position: 1 */
    }; /* bitfield */
  }; /* size: 0x0002 */
} PROCESS_EXECUTION_TRANSITION, *PPROCESS_EXECUTION_TRANSITION; /* size: 0x0002 */

typedef union _PROCESS_EXECUTION_STATE
{
  union
  {
    /* 0x0000 */ char State;
    struct /* bitfield */
    {
      /* 0x0000 */ unsigned char ProcessFrozen : 1; /* bit position: 0 */
      /* 0x0000 */ unsigned char ProcessSwapped : 1; /* bit position: 1 */
      /* 0x0000 */ unsigned char ProcessGraphicsFreezeOptimized : 1; /* bit position: 2 */
      /* 0x0000 */ unsigned char Reserved : 5; /* bit position: 3 */
    }; /* bitfield */
  }; /* size: 0x0001 */
} PROCESS_EXECUTION_STATE, *PPROCESS_EXECUTION_STATE; /* size: 0x0001 */

typedef union _PROCESS_EXECUTION
{
  union
  {
    /* 0x0000 */ volatile int State;
    struct
    {
      /* 0x0000 */ volatile union _PROCESS_EXECUTION_TRANSITION Transition;
      /* 0x0002 */ union _PROCESS_EXECUTION_STATE Current;
      /* 0x0003 */ union _PROCESS_EXECUTION_STATE Requested;
    }; /* size: 0x0004 */
  }; /* size: 0x0004 */
} PROCESS_EXECUTION, *PPROCESS_EXECUTION; /* size: 0x0004 */

typedef struct _EPROCESS
{
  /* 0x0000 */ struct _KPROCESS Pcb;
  /* 0x01c8 */ struct _EX_PUSH_LOCK ProcessLock;
  /* 0x01d0 */ void* UniqueProcessId;
  /* 0x01d8 */ struct _LIST_ENTRY ActiveProcessLinks;
  /* 0x01e8 */ struct _EX_RUNDOWN_REF RundownProtect;
  union
  {
    /* 0x01f0 */ unsigned int Flags2;
    struct /* bitfield */
    {
      /* 0x01f0 */ unsigned int JobNotReallyActive : 1; /* bit position: 0 */
      /* 0x01f0 */ unsigned int AccountingFolded : 1; /* bit position: 1 */
      /* 0x01f0 */ unsigned int NewProcessReported : 1; /* bit position: 2 */
      /* 0x01f0 */ unsigned int ExitProcessReported : 1; /* bit position: 3 */
      /* 0x01f0 */ unsigned int ReportCommitChanges : 1; /* bit position: 4 */
      /* 0x01f0 */ unsigned int LastReportMemory : 1; /* bit position: 5 */
      /* 0x01f0 */ unsigned int ForceWakeCharge : 1; /* bit position: 6 */
      /* 0x01f0 */ unsigned int CrossSessionCreate : 1; /* bit position: 7 */
      /* 0x01f0 */ unsigned int NeedsHandleRundown : 1; /* bit position: 8 */
      /* 0x01f0 */ unsigned int RefTraceEnabled : 1; /* bit position: 9 */
      /* 0x01f0 */ unsigned int PicoCreated : 1; /* bit position: 10 */
      /* 0x01f0 */ unsigned int EmptyJobEvaluated : 1; /* bit position: 11 */
      /* 0x01f0 */ unsigned int DefaultPagePriority : 3; /* bit position: 12 */
      /* 0x01f0 */ unsigned int PrimaryTokenFrozen : 1; /* bit position: 15 */
      /* 0x01f0 */ unsigned int ProcessVerifierTarget : 1; /* bit position: 16 */
      /* 0x01f0 */ unsigned int RestrictSetThreadContext : 1; /* bit position: 17 */
      /* 0x01f0 */ unsigned int AffinityPermanent : 1; /* bit position: 18 */
      /* 0x01f0 */ unsigned int AffinityUpdateEnable : 1; /* bit position: 19 */
      /* 0x01f0 */ unsigned int PropagateNode : 1; /* bit position: 20 */
      /* 0x01f0 */ unsigned int ExplicitAffinity : 1; /* bit position: 21 */
      /* 0x01f0 */ unsigned int Flags2Available1 : 2; /* bit position: 22 */
      /* 0x01f0 */ unsigned int EnableReadVmLogging : 1; /* bit position: 24 */
      /* 0x01f0 */ unsigned int EnableWriteVmLogging : 1; /* bit position: 25 */
      /* 0x01f0 */ unsigned int FatalAccessTerminationRequested : 1; /* bit position: 26 */
      /* 0x01f0 */ unsigned int DisableSystemAllowedCpuSet : 1; /* bit position: 27 */
      /* 0x01f0 */ unsigned int Flags2Available2 : 3; /* bit position: 28 */
      /* 0x01f0 */ unsigned int InPrivate : 1; /* bit position: 31 */
    }; /* bitfield */
  }; /* size: 0x0004 */
  union
  {
    /* 0x01f4 */ unsigned int Flags;
    struct /* bitfield */
    {
      /* 0x01f4 */ unsigned int CreateReported : 1; /* bit position: 0 */
      /* 0x01f4 */ unsigned int NoDebugInherit : 1; /* bit position: 1 */
      /* 0x01f4 */ unsigned int ProcessExiting : 1; /* bit position: 2 */
      /* 0x01f4 */ unsigned int ProcessDelete : 1; /* bit position: 3 */
      /* 0x01f4 */ unsigned int ManageExecutableMemoryWrites : 1; /* bit position: 4 */
      /* 0x01f4 */ unsigned int VmDeleted : 1; /* bit position: 5 */
      /* 0x01f4 */ unsigned int OutswapEnabled : 1; /* bit position: 6 */
      /* 0x01f4 */ unsigned int Outswapped : 1; /* bit position: 7 */
      /* 0x01f4 */ unsigned int FailFastOnCommitFail : 1; /* bit position: 8 */
      /* 0x01f4 */ unsigned int Wow64VaSpace4Gb : 1; /* bit position: 9 */
      /* 0x01f4 */ unsigned int AddressSpaceInitialized : 2; /* bit position: 10 */
      /* 0x01f4 */ unsigned int SetTimerResolution : 1; /* bit position: 12 */
      /* 0x01f4 */ unsigned int BreakOnTermination : 1; /* bit position: 13 */
      /* 0x01f4 */ unsigned int DeprioritizeViews : 1; /* bit position: 14 */
      /* 0x01f4 */ unsigned int WriteWatch : 1; /* bit position: 15 */
      /* 0x01f4 */ unsigned int ProcessInSession : 1; /* bit position: 16 */
      /* 0x01f4 */ unsigned int OverrideAddressSpace : 1; /* bit position: 17 */
      /* 0x01f4 */ unsigned int HasAddressSpace : 1; /* bit position: 18 */
      /* 0x01f4 */ unsigned int LaunchPrefetched : 1; /* bit position: 19 */
      /* 0x01f4 */ unsigned int Reserved : 1; /* bit position: 20 */
      /* 0x01f4 */ unsigned int VmTopDown : 1; /* bit position: 21 */
      /* 0x01f4 */ unsigned int ImageNotifyDone : 1; /* bit position: 22 */
      /* 0x01f4 */ unsigned int PdeUpdateNeeded : 1; /* bit position: 23 */
      /* 0x01f4 */ unsigned int VdmAllowed : 1; /* bit position: 24 */
      /* 0x01f4 */ unsigned int ProcessRundown : 1; /* bit position: 25 */
      /* 0x01f4 */ unsigned int ProcessInserted : 1; /* bit position: 26 */
      /* 0x01f4 */ unsigned int DefaultIoPriority : 3; /* bit position: 27 */
      /* 0x01f4 */ unsigned int ProcessSelfDelete : 1; /* bit position: 30 */
      /* 0x01f4 */ unsigned int SetTimerResolutionLink : 1; /* bit position: 31 */
    }; /* bitfield */
  }; /* size: 0x0004 */
  /* 0x01f8 */ union _LARGE_INTEGER CreateTime;
  /* 0x0200 */ unsigned __int64 ProcessQuotaUsage[2];
  /* 0x0210 */ unsigned __int64 ProcessQuotaPeak[2];
  /* 0x0220 */ unsigned __int64 PeakVirtualSize;
  /* 0x0228 */ unsigned __int64 VirtualSize;
  /* 0x0230 */ struct _LIST_ENTRY SessionProcessLinks;
  union
  {
    /* 0x0240 */ void* ExceptionPortData;
    /* 0x0240 */ unsigned __int64 ExceptionPortValue;
    /* 0x0240 */ unsigned __int64 ExceptionPortState : 3; /* bit position: 0 */
  }; /* size: 0x0008 */
  /* 0x0248 */ struct _EX_FAST_REF Token;
  /* 0x0250 */ unsigned __int64 MmReserved;
  /* 0x0258 */ struct _EX_PUSH_LOCK AddressCreationLock;
  /* 0x0260 */ struct _EX_PUSH_LOCK PageTableCommitmentLock;
  /* 0x0268 */ struct _ETHREAD* RotateInProgress;
  /* 0x0270 */ struct _ETHREAD* ForkInProgress;
  /* 0x0278 */ struct _EJOB* volatile CommitChargeJob;
  /* 0x0280 */ struct _RTL_AVL_TREE CloneRoot;
  /* 0x0288 */ volatile unsigned __int64 NumberOfPrivatePages;
  /* 0x0290 */ volatile unsigned __int64 NumberOfLockedPages;
  /* 0x0298 */ void* Win32Process;
  /* 0x02a0 */ struct _EJOB* volatile Job;
  /* 0x02a8 */ void* SectionObject;
  /* 0x02b0 */ void* SectionBaseAddress;
  /* 0x02b8 */ unsigned int Cookie;
  /* 0x02c0 */ struct _PAGEFAULT_HISTORY* WorkingSetWatch;
  /* 0x02c8 */ void* Win32WindowStation;
  /* 0x02d0 */ void* InheritedFromUniqueProcessId;
  /* 0x02d8 */ volatile unsigned __int64 OwnerProcessId;
  /* 0x02e0 */ struct _PEB* Peb;
  /* 0x02e8 */ struct _PSP_SESSION_SPACE* Session;
  /* 0x02f0 */ void* Spare1;
  /* 0x02f8 */ struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;
  /* 0x0300 */ struct _HANDLE_TABLE* ObjectTable;
  /* 0x0308 */ void* DebugPort;
  /* 0x0310 */ struct _EWOW64PROCESS* WoW64Process;
  /* 0x0318 */ struct _EX_FAST_REF DeviceMap;
  /* 0x0320 */ void* EtwDataSource;
  /* 0x0328 */ unsigned __int64 PageDirectoryPte;
  /* 0x0330 */ struct _FILE_OBJECT* ImageFilePointer;
  /* 0x0338 */ unsigned char ImageFileName[15];
  /* 0x0347 */ unsigned char PriorityClass;
  /* 0x0348 */ void* SecurityPort;
  /* 0x0350 */ struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;
  /* 0x0358 */ struct _LIST_ENTRY JobLinks;
  /* 0x0368 */ void* HighestUserAddress;
  /* 0x0370 */ struct _LIST_ENTRY ThreadListHead;
  /* 0x0380 */ volatile unsigned int ActiveThreads;
  /* 0x0384 */ unsigned int ImagePathHash;
  /* 0x0388 */ unsigned int DefaultHardErrorProcessing;
  /* 0x038c */ int LastThreadExitStatus;
  /* 0x0390 */ struct _EX_FAST_REF PrefetchTrace;
  /* 0x0398 */ void* LockedPagesList;
  /* 0x03a0 */ union _LARGE_INTEGER ReadOperationCount;
  /* 0x03a8 */ union _LARGE_INTEGER WriteOperationCount;
  /* 0x03b0 */ union _LARGE_INTEGER OtherOperationCount;
  /* 0x03b8 */ union _LARGE_INTEGER ReadTransferCount;
  /* 0x03c0 */ union _LARGE_INTEGER WriteTransferCount;
  /* 0x03c8 */ union _LARGE_INTEGER OtherTransferCount;
  /* 0x03d0 */ unsigned __int64 CommitChargeLimit;
  /* 0x03d8 */ volatile unsigned __int64 CommitCharge;
  /* 0x03e0 */ volatile unsigned __int64 CommitChargePeak;
  /* 0x03e8 */ char Vm_padding_[0x18];
  /* 0x0400 */ struct _MMSUPPORT_FULL Vm;
  /* 0x0540 */ struct _LIST_ENTRY MmProcessLinks;
  /* 0x0550 */ volatile unsigned int ModifiedPageCount;
  /* 0x0554 */ int ExitStatus;
  /* 0x0558 */ struct _RTL_AVL_TREE VadRoot;
  /* 0x0560 */ void* VadHint;
  /* 0x0568 */ unsigned __int64 VadCount;
  /* 0x0570 */ volatile unsigned __int64 VadPhysicalPages;
  /* 0x0578 */ unsigned __int64 VadPhysicalPagesLimit;
  /* 0x0580 */ struct _ALPC_PROCESS_CONTEXT AlpcContext;
  /* 0x05a0 */ struct _LIST_ENTRY TimerResolutionLink;
  /* 0x05b0 */ struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;
  /* 0x05b8 */ unsigned int RequestedTimerResolution;
  /* 0x05bc */ unsigned int SmallestTimerResolution;
  /* 0x05c0 */ union _LARGE_INTEGER ExitTime;
  /* 0x05c8 */ struct _INVERTED_FUNCTION_TABLE_KERNEL_MODE* InvertedFunctionTable;
  /* 0x05d0 */ struct _EX_PUSH_LOCK InvertedFunctionTableLock;
  /* 0x05d8 */ unsigned int ActiveThreadsHighWatermark;
  /* 0x05dc */ unsigned int LargePrivateVadCount;
  /* 0x05e0 */ struct _EX_PUSH_LOCK ThreadListLock;
  /* 0x05e8 */ void* WnfContext;
  /* 0x05f0 */ struct _EJOB* ServerSilo;
  /* 0x05f8 */ unsigned char SignatureLevel;
  /* 0x05f9 */ unsigned char SectionSignatureLevel;
  /* 0x05fa */ struct _PS_PROTECTION Protection;
  struct /* bitfield */
  {
    /* 0x05fb */ unsigned char HangCount : 3; /* bit position: 0 */
    /* 0x05fb */ unsigned char GhostCount : 3; /* bit position: 3 */
    /* 0x05fb */ unsigned char PrefilterException : 1; /* bit position: 6 */
  }; /* bitfield */
  union
  {
    /* 0x05fc */ unsigned int Flags3;
    struct /* bitfield */
    {
      /* 0x05fc */ unsigned int Minimal : 1; /* bit position: 0 */
      /* 0x05fc */ unsigned int ReplacingPageRoot : 1; /* bit position: 1 */
      /* 0x05fc */ unsigned int Crashed : 1; /* bit position: 2 */
      /* 0x05fc */ unsigned int JobVadsAreTracked : 1; /* bit position: 3 */
      /* 0x05fc */ unsigned int VadTrackingDisabled : 1; /* bit position: 4 */
      /* 0x05fc */ unsigned int AuxiliaryProcess : 1; /* bit position: 5 */
      /* 0x05fc */ unsigned int SubsystemProcess : 1; /* bit position: 6 */
      /* 0x05fc */ unsigned int IndirectCpuSets : 1; /* bit position: 7 */
      /* 0x05fc */ unsigned int RelinquishedCommit : 1; /* bit position: 8 */
      /* 0x05fc */ unsigned int HighGraphicsPriority : 1; /* bit position: 9 */
      /* 0x05fc */ unsigned int CommitFailLogged : 1; /* bit position: 10 */
      /* 0x05fc */ unsigned int ReserveFailLogged : 1; /* bit position: 11 */
      /* 0x05fc */ unsigned int SystemProcess : 1; /* bit position: 12 */
      /* 0x05fc */ unsigned int AllImagesAtBasePristineBase : 1; /* bit position: 13 */
      /* 0x05fc */ unsigned int AddressPolicyFrozen : 1; /* bit position: 14 */
      /* 0x05fc */ unsigned int ProcessFirstResume : 1; /* bit position: 15 */
      /* 0x05fc */ unsigned int ForegroundExternal : 1; /* bit position: 16 */
      /* 0x05fc */ unsigned int ForegroundSystem : 1; /* bit position: 17 */
      /* 0x05fc */ unsigned int HighMemoryPriority : 1; /* bit position: 18 */
      /* 0x05fc */ unsigned int EnableProcessSuspendResumeLogging : 1; /* bit position: 19 */
      /* 0x05fc */ unsigned int EnableThreadSuspendResumeLogging : 1; /* bit position: 20 */
      /* 0x05fc */ unsigned int SecurityDomainChanged : 1; /* bit position: 21 */
      /* 0x05fc */ unsigned int SecurityFreezeComplete : 1; /* bit position: 22 */
      /* 0x05fc */ unsigned int VmProcessorHost : 1; /* bit position: 23 */
      /* 0x05fc */ unsigned int VmProcessorHostTransition : 1; /* bit position: 24 */
      /* 0x05fc */ unsigned int AltSyscall : 1; /* bit position: 25 */
      /* 0x05fc */ unsigned int TimerResolutionIgnore : 1; /* bit position: 26 */
      /* 0x05fc */ unsigned int DisallowUserTerminate : 1; /* bit position: 27 */
      /* 0x05fc */ unsigned int EnableProcessRemoteExecProtectVmLogging : 1; /* bit position: 28 */
      /* 0x05fc */ unsigned int EnableProcessLocalExecProtectVmLogging : 1; /* bit position: 29 */
      /* 0x05fc */ unsigned int MemoryCompressionProcess : 1; /* bit position: 30 */
      /* 0x05fc */ unsigned int EnableProcessImpersonationLogging : 1; /* bit position: 31 */
    }; /* bitfield */
  }; /* size: 0x0004 */
  /* 0x0600 */ int DeviceAsid;
  /* 0x0608 */ void* SvmData;
  /* 0x0610 */ struct _EX_PUSH_LOCK SvmProcessLock;
  /* 0x0618 */ unsigned __int64 SvmLock;
  /* 0x0620 */ struct _LIST_ENTRY SvmProcessDeviceListHead;
  /* 0x0630 */ unsigned __int64 LastFreezeInterruptTime;
  /* 0x0638 */ struct _PROCESS_DISK_COUNTERS* DiskCounters;
  /* 0x0640 */ void* PicoContext;
  /* 0x0648 */ void* EnclaveTable;
  /* 0x0650 */ unsigned __int64 EnclaveNumber;
  /* 0x0658 */ struct _EX_PUSH_LOCK EnclaveLock;
  /* 0x0660 */ unsigned int HighPriorityFaultsAllowed;
  /* 0x0668 */ struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;
  /* 0x0670 */ void* VmContext;
  /* 0x0678 */ unsigned __int64 SequenceNumber;
  /* 0x0680 */ unsigned __int64 CreateInterruptTime;
  /* 0x0688 */ unsigned __int64 CreateUnbiasedInterruptTime;
  /* 0x0690 */ unsigned __int64 TotalUnbiasedFrozenTime;
  /* 0x0698 */ unsigned __int64 LastAppStateUpdateTime;
  struct /* bitfield */
  {
    /* 0x06a0 */ unsigned __int64 LastAppStateUptime : 61; /* bit position: 0 */
    /* 0x06a0 */ unsigned __int64 LastAppState : 3; /* bit position: 61 */
  }; /* bitfield */
  /* 0x06a8 */ volatile unsigned __int64 SharedCommitCharge;
  /* 0x06b0 */ struct _EX_PUSH_LOCK SharedCommitLock;
  /* 0x06b8 */ struct _LIST_ENTRY SharedCommitLinks;
  union
  {
    struct
    {
      /* 0x06c8 */ unsigned __int64 AllowedCpuSets;
      /* 0x06d0 */ unsigned __int64 DefaultCpuSets;
    }; /* size: 0x0010 */
    struct
    {
      /* 0x06c8 */ unsigned __int64* AllowedCpuSetsIndirect;
      /* 0x06d0 */ unsigned __int64* DefaultCpuSetsIndirect;
    }; /* size: 0x0010 */
  }; /* size: 0x0010 */
  /* 0x06d8 */ void* DiskIoAttribution;
  /* 0x06e0 */ void* DxgProcess;
  /* 0x06e8 */ unsigned int Win32KFilterSet;
  /* 0x06ec */ unsigned short Machine;
  /* 0x06ee */ unsigned char MmSlabIdentity;
  /* 0x06ef */ unsigned char Spare0;
  /* 0x06f0 */ volatile union _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;
  /* 0x06f8 */ volatile unsigned int KTimerSets;
  /* 0x06fc */ volatile unsigned int KTimer2Sets;
  /* 0x0700 */ volatile unsigned int ThreadTimerSets;
  /* 0x0708 */ unsigned __int64 VirtualTimerListLock;
  /* 0x0710 */ struct _LIST_ENTRY VirtualTimerListHead;
  union
  {
    /* 0x0720 */ struct _WNF_STATE_NAME WakeChannel;
    /* 0x0720 */ struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;
  }; /* size: 0x0030 */
  union
  {
    /* 0x0750 */ unsigned int MitigationFlags;
    struct
    {
      struct /* bitfield */
      {
        /* 0x0750 */ unsigned int ControlFlowGuardEnabled : 1; /* bit position: 0 */
        /* 0x0750 */ unsigned int ControlFlowGuardExportSuppressionEnabled : 1; /* bit position: 1 */
        /* 0x0750 */ unsigned int ControlFlowGuardStrict : 1; /* bit position: 2 */
        /* 0x0750 */ unsigned int DisallowStrippedImages : 1; /* bit position: 3 */
        /* 0x0750 */ unsigned int ForceRelocateImages : 1; /* bit position: 4 */
        /* 0x0750 */ unsigned int HighEntropyASLREnabled : 1; /* bit position: 5 */
        /* 0x0750 */ unsigned int StackRandomizationDisabled : 1; /* bit position: 6 */
        /* 0x0750 */ unsigned int ExtensionPointDisable : 1; /* bit position: 7 */
        /* 0x0750 */ unsigned int DisableDynamicCode : 1; /* bit position: 8 */
        /* 0x0750 */ unsigned int DisableDynamicCodeAllowOptOut : 1; /* bit position: 9 */
        /* 0x0750 */ unsigned int DisableDynamicCodeAllowRemoteDowngrade : 1; /* bit position: 10 */
        /* 0x0750 */ unsigned int AuditDisableDynamicCode : 1; /* bit position: 11 */
        /* 0x0750 */ unsigned int DisallowWin32kSystemCalls : 1; /* bit position: 12 */
        /* 0x0750 */ unsigned int AuditDisallowWin32kSystemCalls : 1; /* bit position: 13 */
        /* 0x0750 */ unsigned int EnableFilteredWin32kAPIs : 1; /* bit position: 14 */
        /* 0x0750 */ unsigned int AuditFilteredWin32kAPIs : 1; /* bit position: 15 */
        /* 0x0750 */ unsigned int DisableNonSystemFonts : 1; /* bit position: 16 */
        /* 0x0750 */ unsigned int AuditNonSystemFontLoading : 1; /* bit position: 17 */
        /* 0x0750 */ unsigned int PreferSystem32Images : 1; /* bit position: 18 */
        /* 0x0750 */ unsigned int ProhibitRemoteImageMap : 1; /* bit position: 19 */
        /* 0x0750 */ unsigned int AuditProhibitRemoteImageMap : 1; /* bit position: 20 */
        /* 0x0750 */ unsigned int ProhibitLowILImageMap : 1; /* bit position: 21 */
        /* 0x0750 */ unsigned int AuditProhibitLowILImageMap : 1; /* bit position: 22 */
        /* 0x0750 */ unsigned int SignatureMitigationOptIn : 1; /* bit position: 23 */
        /* 0x0750 */ unsigned int AuditBlockNonMicrosoftBinaries : 1; /* bit position: 24 */
        /* 0x0750 */ unsigned int AuditBlockNonMicrosoftBinariesAllowStore : 1; /* bit position: 25 */
        /* 0x0750 */ unsigned int LoaderIntegrityContinuityEnabled : 1; /* bit position: 26 */
        /* 0x0750 */ unsigned int AuditLoaderIntegrityContinuity : 1; /* bit position: 27 */
        /* 0x0750 */ unsigned int EnableModuleTamperingProtection : 1; /* bit position: 28 */
        /* 0x0750 */ unsigned int EnableModuleTamperingProtectionNoInherit : 1; /* bit position: 29 */
        /* 0x0750 */ unsigned int RestrictIndirectBranchPrediction : 1; /* bit position: 30 */
        /* 0x0750 */ unsigned int IsolateSecurityDomain : 1; /* bit position: 31 */
      }; /* bitfield */
    } /* size: 0x0004 */ MitigationFlagsValues;
  }; /* size: 0x0004 */
  union
  {
    /* 0x0754 */ unsigned int MitigationFlags2;
    struct
    {
      struct /* bitfield */
      {
        /* 0x0754 */ unsigned int EnableExportAddressFilter : 1; /* bit position: 0 */
        /* 0x0754 */ unsigned int AuditExportAddressFilter : 1; /* bit position: 1 */
        /* 0x0754 */ unsigned int EnableExportAddressFilterPlus : 1; /* bit position: 2 */
        /* 0x0754 */ unsigned int AuditExportAddressFilterPlus : 1; /* bit position: 3 */
        /* 0x0754 */ unsigned int EnableRopStackPivot : 1; /* bit position: 4 */
        /* 0x0754 */ unsigned int AuditRopStackPivot : 1; /* bit position: 5 */
        /* 0x0754 */ unsigned int EnableRopCallerCheck : 1; /* bit position: 6 */
        /* 0x0754 */ unsigned int AuditRopCallerCheck : 1; /* bit position: 7 */
        /* 0x0754 */ unsigned int EnableRopSimExec : 1; /* bit position: 8 */
        /* 0x0754 */ unsigned int AuditRopSimExec : 1; /* bit position: 9 */
        /* 0x0754 */ unsigned int EnableImportAddressFilter : 1; /* bit position: 10 */
        /* 0x0754 */ unsigned int AuditImportAddressFilter : 1; /* bit position: 11 */
        /* 0x0754 */ unsigned int DisablePageCombine : 1; /* bit position: 12 */
        /* 0x0754 */ unsigned int SpeculativeStoreBypassDisable : 1; /* bit position: 13 */
        /* 0x0754 */ unsigned int CetUserShadowStacks : 1; /* bit position: 14 */
        /* 0x0754 */ unsigned int AuditCetUserShadowStacks : 1; /* bit position: 15 */
        /* 0x0754 */ unsigned int AuditCetUserShadowStacksLogged : 1; /* bit position: 16 */
        /* 0x0754 */ unsigned int UserCetSetContextIpValidation : 1; /* bit position: 17 */
        /* 0x0754 */ unsigned int AuditUserCetSetContextIpValidation : 1; /* bit position: 18 */
        /* 0x0754 */ unsigned int AuditUserCetSetContextIpValidationLogged : 1; /* bit position: 19 */
        /* 0x0754 */ unsigned int CetUserShadowStacksStrictMode : 1; /* bit position: 20 */
        /* 0x0754 */ unsigned int BlockNonCetBinaries : 1; /* bit position: 21 */
        /* 0x0754 */ unsigned int BlockNonCetBinariesNonEhcont : 1; /* bit position: 22 */
        /* 0x0754 */ unsigned int AuditBlockNonCetBinaries : 1; /* bit position: 23 */
        /* 0x0754 */ unsigned int AuditBlockNonCetBinariesLogged : 1; /* bit position: 24 */
        /* 0x0754 */ unsigned int XtendedControlFlowGuard_Deprecated : 1; /* bit position: 25 */
        /* 0x0754 */ unsigned int AuditXtendedControlFlowGuard_Deprecated : 1; /* bit position: 26 */
        /* 0x0754 */ unsigned int PointerAuthUserIp : 1; /* bit position: 27 */
        /* 0x0754 */ unsigned int AuditPointerAuthUserIp : 1; /* bit position: 28 */
        /* 0x0754 */ unsigned int AuditPointerAuthUserIpLogged : 1; /* bit position: 29 */
        /* 0x0754 */ unsigned int CetDynamicApisOutOfProcOnly : 1; /* bit position: 30 */
        /* 0x0754 */ unsigned int UserCetSetContextIpValidationRelaxedMode : 1; /* bit position: 31 */
      }; /* bitfield */
    } /* size: 0x0004 */ MitigationFlags2Values;
  }; /* size: 0x0004 */
  /* 0x0758 */ void* PartitionObject;
  /* 0x0760 */ unsigned __int64 SecurityDomain;
  /* 0x0768 */ unsigned __int64 ParentSecurityDomain;
  /* 0x0770 */ void* CoverageSamplerContext;
  /* 0x0778 */ void* MmHotPatchContext;
  /* 0x0780 */ struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree;
  /* 0x0788 */ struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock;
  /* 0x0790 */ struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges;
  /* 0x07a0 */ unsigned int DisabledComponentFlags;
  /* 0x07a4 */ volatile int PageCombineSequence;
  /* 0x07a8 */ struct _EX_PUSH_LOCK EnableOptionalXStateFeaturesLock;
  /* 0x07b0 */ unsigned int* volatile PathRedirectionHashes;
  /* 0x07b8 */ struct _PS_SYSCALL_PROVIDER* SyscallProvider;
  /* 0x07c0 */ struct _LIST_ENTRY SyscallProviderProcessLinks;
  /* 0x07d0 */ struct _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT SyscallProviderDispatchContext;
  union
  {
    /* 0x07d8 */ unsigned int MitigationFlags3;
    struct
    {
      struct /* bitfield */
      {
        /* 0x07d8 */ unsigned int RestrictCoreSharing : 1; /* bit position: 0 */
        /* 0x07d8 */ unsigned int DisallowFsctlSystemCalls : 1; /* bit position: 1 */
        /* 0x07d8 */ unsigned int AuditDisallowFsctlSystemCalls : 1; /* bit position: 2 */
        /* 0x07d8 */ unsigned int MitigationFlags3Spare : 29; /* bit position: 3 */
      }; /* bitfield */
    } /* size: 0x0004 */ MitigationFlags3Values;
  }; /* size: 0x0004 */
  union
  {
    /* 0x07dc */ unsigned int Flags4;
    struct /* bitfield */
    {
      /* 0x07dc */ unsigned int ThreadWasActive : 1; /* bit position: 0 */
      /* 0x07dc */ unsigned int MinimalTerminate : 1; /* bit position: 1 */
      /* 0x07dc */ unsigned int ImageExpansionDisable : 1; /* bit position: 2 */
      /* 0x07dc */ unsigned int SessionFirstProcess : 1; /* bit position: 3 */
    }; /* bitfield */
  }; /* size: 0x0004 */
  union
  {
    /* 0x07e0 */ unsigned int SyscallUsage;
    struct
    {
      struct /* bitfield */
      {
        /* 0x07e0 */ unsigned int SystemModuleInformation : 1; /* bit position: 0 */
        /* 0x07e0 */ unsigned int SystemModuleInformationEx : 1; /* bit position: 1 */
        /* 0x07e0 */ unsigned int SystemLocksInformation : 1; /* bit position: 2 */
        /* 0x07e0 */ unsigned int SystemStackTraceInformation : 1; /* bit position: 3 */
        /* 0x07e0 */ unsigned int SystemHandleInformation : 1; /* bit position: 4 */
        /* 0x07e0 */ unsigned int SystemExtendedHandleInformation : 1; /* bit position: 5 */
        /* 0x07e0 */ unsigned int SystemObjectInformation : 1; /* bit position: 6 */
        /* 0x07e0 */ unsigned int SystemBigPoolInformation : 1; /* bit position: 7 */
        /* 0x07e0 */ unsigned int SystemExtendedProcessInformation : 1; /* bit position: 8 */
        /* 0x07e0 */ unsigned int SystemSessionProcessInformation : 1; /* bit position: 9 */
        /* 0x07e0 */ unsigned int SystemMemoryTopologyInformation : 1; /* bit position: 10 */
        /* 0x07e0 */ unsigned int SystemMemoryChannelInformation : 1; /* bit position: 11 */
        /* 0x07e0 */ unsigned int SystemUnused : 1; /* bit position: 12 */
        /* 0x07e0 */ unsigned int SystemPlatformBinaryInformation : 1; /* bit position: 13 */
        /* 0x07e0 */ unsigned int SystemFirmwareTableInformation : 1; /* bit position: 14 */
        /* 0x07e0 */ unsigned int SystemBootMetadataInformation : 1; /* bit position: 15 */
        /* 0x07e0 */ unsigned int SystemWheaIpmiHardwareInformation : 1; /* bit position: 16 */
        /* 0x07e0 */ unsigned int SystemSuperfetchPrefetch : 1; /* bit position: 17 */
        /* 0x07e0 */ unsigned int SystemSuperfetchPfnQuery : 1; /* bit position: 18 */
        /* 0x07e0 */ unsigned int SystemSuperfetchPrivSourceQuery : 1; /* bit position: 19 */
        /* 0x07e0 */ unsigned int SystemSuperfetchMemoryListQuery : 1; /* bit position: 20 */
        /* 0x07e0 */ unsigned int SystemSuperfetchMemoryRangesQuery : 1; /* bit position: 21 */
        /* 0x07e0 */ unsigned int SystemSuperfetchPfnSetPriority : 1; /* bit position: 22 */
        /* 0x07e0 */ unsigned int SystemSuperfetchMovePages : 1; /* bit position: 23 */
        /* 0x07e0 */ unsigned int SystemSuperfetchPfnSetPageHeat : 1; /* bit position: 24 */
        /* 0x07e0 */ unsigned int SysDbgGetTriageDump : 1; /* bit position: 25 */
        /* 0x07e0 */ unsigned int SysDbgGetLiveKernelDump : 1; /* bit position: 26 */
        /* 0x07e0 */ unsigned int SyscallUsageValuesSpare : 5; /* bit position: 27 */
      }; /* bitfield */
    } /* size: 0x0004 */ SyscallUsageValues;
  }; /* size: 0x0004 */
  /* 0x07e4 */ int SupervisorDeviceAsid;
  /* 0x07e8 */ void* SupervisorSvmData;
  /* 0x07f0 */ struct _PROCESS_NETWORK_COUNTERS* NetworkCounters;
  /* 0x07f8 */ union _PROCESS_EXECUTION Execution;
  /* 0x0800 */ void* ThreadIndexTable;
  /* 0x0808 */ int __PADDING__[14];
} EPROCESS, *PEPROCESS; /* size: 0x0840 */

typedef struct _KLDR_DATA_TABLE_ENTRY
{
  /* 0x0000 */ struct _LIST_ENTRY InLoadOrderLinks;
  /* 0x0010 */ void* ExceptionTable;
  /* 0x0018 */ unsigned int ExceptionTableSize;
  /* 0x0020 */ void* GpValue;
  /* 0x0028 */ struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
  /* 0x0030 */ void* DllBase;
  /* 0x0038 */ void* EntryPoint;
  /* 0x0040 */ unsigned int SizeOfImage;
  /* 0x0048 */ struct _UNICODE_STRING FullDllName;
  /* 0x0058 */ struct _UNICODE_STRING BaseDllName;
  /* 0x0068 */ unsigned int Flags;
  /* 0x006c */ unsigned short LoadCount;
  union
  {
    union
    {
      struct /* bitfield */
      {
        /* 0x006e */ unsigned short SignatureLevel : 4; /* bit position: 0 */
        /* 0x006e */ unsigned short SignatureType : 3; /* bit position: 4 */
        /* 0x006e */ unsigned short Frozen : 2; /* bit position: 7 */
        /* 0x006e */ unsigned short HotPatch : 1; /* bit position: 9 */
        /* 0x006e */ unsigned short Unused : 6; /* bit position: 10 */
      }; /* bitfield */
      /* 0x006e */ unsigned short EntireField;
    }; /* size: 0x0002 */
  } /* size: 0x0002 */ u1;
  /* 0x0070 */ void* SectionPointer;
  /* 0x0078 */ unsigned int CheckSum;
  /* 0x007c */ unsigned int CoverageSectionSize;
  /* 0x0080 */ void* CoverageSection;
  /* 0x0088 */ void* LoadedImports;
  union
  {
    /* 0x0090 */ void* Spare;
    /* 0x0090 */ struct _KLDR_DATA_TABLE_ENTRY* NtDataTableEntry;
  }; /* size: 0x0008 */
  /* 0x0098 */ unsigned int SizeOfImageNotRounded;
  /* 0x009c */ unsigned int TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY; /* size: 0x00a0 */

typedef void* HANDLE;
typedef void* PVOID;
typedef unsigned int ULONG;

typedef struct _CLIENT_ID
{
  /* 0x0000 */ PVOID UniqueProcess;
  /* 0x0008 */ PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID; /* size: 0x0010 */

typedef struct _KTHREAD
{
  /* 0x0000 */ struct _DISPATCHER_HEADER Header;
  /* 0x0018 */ unsigned char Padding0[0x80];
  /* 0x0098 */ unsigned char ApcState[0x30];
  /* 0x00c8 */ unsigned char Padding1[0x158];
  /* 0x0220 */ struct _KPROCESS* Process;
  /* 0x0228 */ unsigned char Padding2[0x258];
} KTHREAD, *PKTHREAD; /* size: 0x0480 */

typedef struct _ETHREAD
{
  /* 0x0000 */ struct _KTHREAD Tcb;
  /* 0x0480 */ unsigned char Padding0[0x20];
  /* 0x04a0 */ PVOID StartAddress;
  /* 0x04a8 */ unsigned char Padding1[0x20];
  /* 0x04c8 */ struct _CLIENT_ID Cid;
  /* 0x04d8 */ unsigned char Padding2[0x48];
  /* 0x0520 */ PVOID Win32StartAddress;
  /* 0x0528 */ unsigned char Padding3[0x3D8];
} ETHREAD, *PETHREAD; /* size: 0x0900 */

typedef struct _OBJECT_HEADER
{
  /* 0x0000 */ __int64 PointerCount;
  /* 0x0008 */ __int64 HandleCount;
  /* 0x0010 */ void* Lock;
  /* 0x0018 */ unsigned char TypeIndex;
  /* 0x0019 */ unsigned char TraceFlags;
  /* 0x001a */ unsigned char InfoMask;
  /* 0x001b */ unsigned char Flags;
  /* 0x001c */ unsigned int Reserved;
  /* 0x0020 */ void* ObjectCreateInfo;
  /* 0x0028 */ void* SecurityDescriptor;
} OBJECT_HEADER, *POBJECT_HEADER; /* size: 0x0030 */

typedef struct _PEB64
{
  /* 0x0000 */ unsigned char InheritedAddressSpace;
  /* 0x0001 */ unsigned char ReadImageFileExecOptions;
  /* 0x0002 */ unsigned char BeingDebugged;
  /* 0x0003 */ unsigned char BitField;
  /* 0x0004 */ unsigned char Padding0[4];
  /* 0x0008 */ unsigned __int64 Mutant;
  /* 0x0010 */ unsigned __int64 ImageBaseAddress;
  /* 0x0018 */ unsigned __int64 Ldr;
  /* 0x0020 */ unsigned __int64 ProcessParameters;
  /* 0x0028 */ unsigned __int64 SubSystemData;
  /* 0x0030 */ unsigned __int64 ProcessHeap;
  /* 0x0038 */ unsigned __int64 FastPebLock;
  /* 0x0040 */ unsigned __int64 AtlThunkSListPtr;
  /* 0x0048 */ unsigned __int64 IFEOKey;
  /* 0x0050 */ unsigned int CrossProcessFlags;
  /* 0x0054 */ unsigned char Padding1[4];
  /* 0x0058 */ unsigned __int64 KernelCallbackTable;
  /* 0x0060 */ unsigned int SystemReserved;
  /* 0x0064 */ unsigned int AtlThunkSListPtr32;
  /* 0x0068 */ unsigned __int64 ApiSetMap;
  /* 0x0070 */ unsigned int TlsExpansionCounter;
  /* 0x0074 */ unsigned char Padding2[4];
  /* 0x0078 */ unsigned __int64 TlsBitmap;
  /* 0x0080 */ unsigned int TlsBitmapBits[2];
  /* 0x0088 */ unsigned __int64 ReadOnlySharedMemoryBase;
  /* 0x0090 */ unsigned __int64 SharedData;
  /* 0x0098 */ unsigned __int64 ReadOnlyStaticServerData;
  /* 0x00a0 */ unsigned __int64 AnsiCodePageData;
  /* 0x00a8 */ unsigned __int64 OemCodePageData;
  /* 0x00b0 */ unsigned __int64 UnicodeCaseTableData;
  /* 0x00b8 */ unsigned int NumberOfProcessors;
  /* 0x00bc */ unsigned int NtGlobalFlag;
  /* 0x00c0 */ unsigned __int64 CriticalSectionTimeout;
  /* 0x00c8 */ unsigned __int64 HeapSegmentReserve;
  /* 0x00d0 */ unsigned __int64 HeapSegmentCommit;
  /* 0x00d8 */ unsigned __int64 HeapDeCommitTotalFreeThreshold;
  /* 0x00e0 */ unsigned __int64 HeapDeCommitFreeBlockThreshold;
  /* 0x00e8 */ unsigned int NumberOfHeaps;
  /* 0x00ec */ unsigned int MaximumNumberOfHeaps;
  /* 0x00f0 */ unsigned __int64 ProcessHeaps;
  /* 0x00f8 */ unsigned __int64 GdiSharedHandleTable;
  /* 0x0100 */ unsigned __int64 ProcessStarterHelper;
  /* 0x0108 */ unsigned int GdiDCAttributeList;
  /* 0x010c */ unsigned char Padding3[4];
  /* 0x0110 */ unsigned __int64 LoaderLock;
  /* 0x0118 */ unsigned int OSMajorVersion;
  /* 0x011c */ unsigned int OSMinorVersion;
  /* 0x0120 */ unsigned short OSBuildNumber;
  /* 0x0122 */ unsigned short OSCSDVersion;
  /* 0x0124 */ unsigned int OSPlatformId;
  /* 0x0128 */ unsigned int ImageSubsystem;
  /* 0x012c */ unsigned int ImageSubsystemMajorVersion;
  /* 0x0130 */ unsigned int ImageSubsystemMinorVersion;
} PEB64, *PPEB64; /* size: 0x0134 */

constexpr std::size_t peb64_alloc_size = 0x800;

typedef struct _NT_TIB64
{
  /* 0x0000 */ unsigned __int64 ExceptionList;
  /* 0x0008 */ unsigned __int64 StackBase;
  /* 0x0010 */ unsigned __int64 StackLimit;
  /* 0x0018 */ unsigned __int64 SubSystemTib;
  /* 0x0020 */ unsigned __int64 FiberData;
  /* 0x0028 */ unsigned __int64 ArbitraryUserPointer;
  /* 0x0030 */ unsigned __int64 Self;
} NT_TIB64; /* size: 0x0038 */

typedef struct _CLIENT_ID64
{
  /* 0x0000 */ unsigned __int64 UniqueProcess;
  /* 0x0008 */ unsigned __int64 UniqueThread;
} CLIENT_ID64; /* size: 0x0010 */

typedef struct _TEB64
{
  /* 0x0000 */ _NT_TIB64 NtTib;
  /* 0x0038 */ unsigned __int64 EnvironmentPointer;
  /* 0x0040 */ _CLIENT_ID64 ClientId;
  /* 0x0050 */ unsigned __int64 ActiveRpcHandle;
  /* 0x0058 */ unsigned __int64 ThreadLocalStoragePointer;
  /* 0x0060 */ unsigned __int64 ProcessEnvironmentBlock;
} TEB64, *PTEB64; /* size: 0x0068 */

constexpr std::size_t teb64_alloc_size = 0x2000;

typedef struct _UNICODE_STRING64
{
  /* 0x0000 */ unsigned short Length;
  /* 0x0002 */ unsigned short MaximumLength;
  /* 0x0004 */ unsigned char _pad[4];
  /* 0x0008 */ unsigned __int64 Buffer;
} UNICODE_STRING64; /* size: 0x0010 */

typedef struct _LIST_ENTRY64
{
  /* 0x0000 */ unsigned __int64 Flink;
  /* 0x0008 */ unsigned __int64 Blink;
} LIST_ENTRY64; /* size: 0x0010 */

typedef struct _PEB_LDR_DATA64
{
  /* 0x0000 */ unsigned int Length;
  /* 0x0004 */ unsigned char Initialized;
  /* 0x0005 */ unsigned char _pad0[3];
  /* 0x0008 */ unsigned __int64 SsHandle;
  /* 0x0010 */ _LIST_ENTRY64 InLoadOrderModuleList;
  /* 0x0020 */ _LIST_ENTRY64 InMemoryOrderModuleList;
  /* 0x0030 */ _LIST_ENTRY64 InInitializationOrderModuleList;
  /* 0x0040 */ unsigned __int64 EntryInProgress;
  /* 0x0048 */ unsigned char ShutdownInProgress;
  /* 0x0049 */ unsigned char _pad1[7];
  /* 0x0050 */ unsigned __int64 ShutdownThreadId;
} PEB_LDR_DATA64; /* size: 0x0058 */

constexpr std::size_t peb_ldr_data64_alloc_size = 0x58;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
  /* 0x0000 */ _LIST_ENTRY64 InLoadOrderLinks;
  /* 0x0010 */ _LIST_ENTRY64 InMemoryOrderLinks;
  /* 0x0020 */ _LIST_ENTRY64 InInitializationOrderLinks;
  /* 0x0030 */ unsigned __int64 DllBase;
  /* 0x0038 */ unsigned __int64 EntryPoint;
  /* 0x0040 */ unsigned int SizeOfImage;
  /* 0x0044 */ unsigned int _pad0;
  /* 0x0048 */ _UNICODE_STRING64 FullDllName;
  /* 0x0058 */ _UNICODE_STRING64 BaseDllName;
  /* 0x0068 */ unsigned int Flags;
  /* 0x006c */ unsigned short ObsoleteLoadCount;
  /* 0x006e */ unsigned short TlsIndex;
  /* 0x0070 */ _LIST_ENTRY64 HashLinks;
} LDR_DATA_TABLE_ENTRY64; /* size: 0x0080 */

constexpr std::size_t ldr_data_table_entry64_alloc_size = 0x120;

static_assert(sizeof(_UNICODE_STRING64) == 0x10);
static_assert(sizeof(_LIST_ENTRY64) == 0x10);

static_assert(sizeof(_PEB_LDR_DATA64) == 0x58);
static_assert(offsetof(_PEB_LDR_DATA64, Initialized) == 0x04);
static_assert(offsetof(_PEB_LDR_DATA64, InLoadOrderModuleList) == 0x10);
static_assert(offsetof(_PEB_LDR_DATA64, InMemoryOrderModuleList) == 0x20);
static_assert(offsetof(_PEB_LDR_DATA64, InInitializationOrderModuleList) == 0x30);

static_assert(offsetof(_LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks) == 0x00);
static_assert(offsetof(_LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks) == 0x10);
static_assert(offsetof(_LDR_DATA_TABLE_ENTRY64, InInitializationOrderLinks) == 0x20);
static_assert(offsetof(_LDR_DATA_TABLE_ENTRY64, DllBase) == 0x30);
static_assert(offsetof(_LDR_DATA_TABLE_ENTRY64, EntryPoint) == 0x38);
static_assert(offsetof(_LDR_DATA_TABLE_ENTRY64, SizeOfImage) == 0x40);
static_assert(offsetof(_LDR_DATA_TABLE_ENTRY64, FullDllName) == 0x48);
static_assert(offsetof(_LDR_DATA_TABLE_ENTRY64, BaseDllName) == 0x58);
static_assert(offsetof(_LDR_DATA_TABLE_ENTRY64, Flags) == 0x68);
static_assert(offsetof(_LDR_DATA_TABLE_ENTRY64, ObsoleteLoadCount) == 0x6C);
static_assert(offsetof(_LDR_DATA_TABLE_ENTRY64, HashLinks) == 0x70);

static_assert(sizeof(_NT_TIB64) == 0x38);
static_assert(offsetof(_NT_TIB64, StackBase) == 0x08);
static_assert(offsetof(_NT_TIB64, StackLimit) == 0x10);
static_assert(offsetof(_NT_TIB64, Self) == 0x30);
static_assert(offsetof(_TEB64, ClientId.UniqueProcess) == 0x40);
static_assert(offsetof(_TEB64, ClientId.UniqueThread) == 0x48);
static_assert(offsetof(_TEB64, ProcessEnvironmentBlock) == 0x60);

static_assert(offsetof(_PEB64, BeingDebugged) == 0x02);
static_assert(offsetof(_PEB64, ImageBaseAddress) == 0x10);
static_assert(offsetof(_PEB64, Ldr) == 0x18);
static_assert(offsetof(_PEB64, ProcessParameters) == 0x20);
static_assert(offsetof(_PEB64, ProcessHeap) == 0x30);
static_assert(offsetof(_PEB64, ApiSetMap) == 0x68);
static_assert(offsetof(_PEB64, AnsiCodePageData) == 0xA0);
static_assert(offsetof(_PEB64, NumberOfProcessors) == 0xB8);
static_assert(offsetof(_PEB64, HeapSegmentReserve) == 0xC8);
static_assert(offsetof(_PEB64, MaximumNumberOfHeaps) == 0xEC);
static_assert(offsetof(_PEB64, GdiSharedHandleTable) == 0xF8);
static_assert(offsetof(_PEB64, OSMajorVersion) == 0x118);
static_assert(offsetof(_PEB64, OSBuildNumber) == 0x120);
static_assert(offsetof(_PEB64, ImageSubsystem) == 0x128);
static_assert(offsetof(_PEB64, ImageSubsystemMinorVersion) == 0x130);

static_assert(offsetof(_EPROCESS, UniqueProcessId) == 0x1D0);
static_assert(offsetof(_EPROCESS, ActiveProcessLinks) == 0x1D8);
static_assert(offsetof(_EPROCESS, ImageFileName) == 0x338);
static_assert(sizeof(_EPROCESS) == 0x840);
static_assert(offsetof(_ETHREAD, StartAddress) == 0x4A0);
static_assert(offsetof(_ETHREAD, Cid) == 0x4C8);
static_assert(offsetof(_ETHREAD, Win32StartAddress) == 0x520);
static_assert(sizeof(_ETHREAD) == 0x900);
static_assert(offsetof(_KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks) == 0x000);
static_assert(offsetof(_KLDR_DATA_TABLE_ENTRY, DllBase) == 0x030);
static_assert(offsetof(_KLDR_DATA_TABLE_ENTRY, EntryPoint) == 0x038);
static_assert(offsetof(_KLDR_DATA_TABLE_ENTRY, SizeOfImage) == 0x040);
static_assert(sizeof(_KLDR_DATA_TABLE_ENTRY) == 0x0A0);
static_assert(sizeof(_OBJECT_HEADER) == 0x30);
