import winim

import utils/[gpa, gmh, hash, stdio, str]

proc main() {.exportc: "Main".} =
  var 
    hKernel32     = gmh("KERNEL32.DLL")
    pHeapAlloc    = gpa(hKernel32, "HeapAlloc", HeapAlloc)
    pGetProcessHeap = gpa(hKernel32, "GetProcessHeap", GetProcessHeap)

  PRINTA("[+] HeapAlloc: %p\n".cstring, cast[int](pHeapAlloc))
  PRINTA("[+] GetProcessHeap: %p\n".cstring, cast[int](pGetProcessHeap))

  var p = pHeapAlloc(pGetProcessHeap(), 0, 0x1000)
  PRINTA("[+] Heap ptr: %p\n".cstring, cast[int](p))

  var test = "Test String Data\0".cstring
  copyMem(p, test[0].addr, strlenA(cast[int](test[0].addr)))
  PRINTA("[+] p contains: %s\n", p)

proc start() {.asmNoStackframe, exportc: "start".} =
  asm """
    push rsi
    mov rsi, rsp
    and rsp, 0xfffffffffffffff0
    sub rsp, 0x20
    call Main
    mov rsp, rsi
    pop rsi
    ret
  """

when isMainModule:
  start()