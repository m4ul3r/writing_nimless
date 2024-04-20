import winim 
import utils/[stdio, stackstr]

proc main(): int {.exportc: "Main".} =
  var test1 {.stackStringA.} = "http://127.0.0.1:1337/cat.exe\n"
  var test2 {.stackStringW.} = "bsideskc420\n"


  PRINTA(CPTR(test1))

  dumpHex(CWPTR(test2), sizeof(test2))


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


