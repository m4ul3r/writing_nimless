import winim 
import utils/[stdio, stackstr]

proc main(): int {.exportc: "Main".} =
  var test {.stackStringA.} = "TESTTEST"
  PRINTA(CPTR(test))



proc start() {.asmNoStackframe, codegenDecl: "__attribute__((section (\".text\"))) $# $#$#", exportc: "start".} =
  asm """
    and rsp, 0xfffffffffffffff0
    sub rsp, 0x10
    call Main
    add rsp, 0x10
    ret
  """

when isMainModule:
  start()


