## nimless template - the two-symbol entry contract plus a runnable body.
##
##   Main  - a normal `{.exportc.}` proc; it is a callee, not the entry point.
##   start - the real entry: `.text`-pinned via codegenDecl, aligns the stack,
##           calls Main, returns. `-Wl,-estart` in nim.cfg points the PE entry here.
##
## Build (from this directory) - options must come BEFORE the project file:
##   nim c -d:mingw -d:malDebug -o:verify_debug.exe main.nim   # PRINTA + console
##   nim c -d:mingw -o:verify_stripped.exe main.nim            # release, quiet
## See reference/build.md for the flags and reference/runtime.md for the instance.
import winim/lean

import instance
import utils/[stdio, stackstr]

{.passC:"-masm=intel".}

proc main() {.exportc: "Main".} =
  discard init(ninst)

  PRINTA("[+] nimless template: no runtime, no imports\n".cstring)

  var s {.stackStringA.} = "stack string"
  PRINTA("[+] %s at %p\n".cstring, cast[cstring](s[0].addr), cast[int](s[0].addr))

  ninst.Win32.ExitProcess(42)

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
