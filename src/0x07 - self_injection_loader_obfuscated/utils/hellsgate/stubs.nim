from winim import NTSTATUS, WORD

var wSystemCall*: WORD

proc HellsGate*(wSys: WORD) {.inline.} = 
  wSystemCall = wSys

proc HellsDescent*(arg1: auto): NTSTATUS {.asmNoStackFrame, varargs.} = 
  asm """
    mov r10, rcx
    mov rax, `wSystemCall`
    syscall
    ret
  """



