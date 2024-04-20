import winim
import ./[gmh, gpa]

proc antiDbgNtProcessDebugFlags*(): bool =
  var 
    status: NTSTATUS 
    uInherit: ULONG
    hNtdll = gmh("ntdll.dll")
    pNtQueryInformationProcess = gpa(hNtdll, "NtQueryInformationProcess", NtQueryInformationProcess)
  status = pNtQueryInformationProcess(cast[HANDLE](-1), cast[int32](31), uInherit.addr, cast[ULONG](sizeof(ULONG)), NULL)
  if status == 0 and uInherit == 0:
    return true
  return false