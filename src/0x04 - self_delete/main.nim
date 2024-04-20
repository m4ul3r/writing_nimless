import winim 

import self_delete

proc main(): int {.exportc: "Main".} =
  var r = deleteSelf()
  if r == true:
    return 1
  else:
    return 0

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


