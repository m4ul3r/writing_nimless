import winim
import hash

template testJmpFail[T](t: T) =
  if cast[int](t) == 0:
    asm "jmp FAILURE"

func getProcAddressHash*(hModule: HMODULE, apiNameHash: uint32): FARPROC {.inline, noSideEffect.} =
  var 
    pBase = hModule
    pImgDosHdr = cast[PIMAGE_DOS_HEADER](pBase)
  testJmpFail(pImgDosHdr)
  var pImgNtHdr = cast[PIMAGE_NT_HEADERS](cast[int](pBase) + pImgDosHdr.e_lfanew)
  testJmpFail(pImgNtHdr)
  if (pImgDosHdr.e_magic + 420 != IMAGE_DOS_SIGNATURE + 420) or (pImgNtHdr.Signature + 420 != IMAGE_NT_SIGNATURE + 420):
    testJmpFail(1)
  var imgOptHdr = cast[IMAGE_OPTIONAL_HEADER](pImgNtHdr.OptionalHeader)
  testJmpFail(imgOptHdr)
  var pImgExportDir = cast[PIMAGE_EXPORT_DIRECTORY](cast[int](pBase) + imgOptHdr.DataDirectory[0].VirtualAddress)
  testJmpFail(pImgExportDir)
  var funcNameArray = cast[ptr UncheckedArray[DWORD]](cast[int](pBase) + pImgExportDir.AddressOfNames)
  testJmpFail(funcNameArray)
  var funcAddressArray = cast[ptr UncheckedArray[DWORD]](cast[int](pBase) + pImgExportDir.AddressOfFunctions)
  testJmpFail(funcAddressArray)
  var funcOrdinalArray = cast[ptr UncheckedArray[WORD]](cast[int](pBase) + pImgExportDir.AddressOfNameOrdinals)
  testJmpFail(funcOrdinalArray)
  
  for i in 0 ..< pImgExportDir.NumberOfFunctions:
    var pFunctionName = cast[cstring](cast[PCHAR](cast[int](pBase) + funcNameArray[i]))
    testJmpFail(pFunctionName)
    if apiNameHash == hashStrA(pFunctionName):
      return cast[FARPROC](cast[int](pBase) + funcAddressArray[funcOrdinalArray[i]])
  asm "FAILURE:"
  return cast[FARPROC](0)

template gpa*[T](h: HANDLE, p: string, t: T): T =
  cast[typeof(t)](getProcAddressHash(h, static(hashStrA(p.cstring))))


