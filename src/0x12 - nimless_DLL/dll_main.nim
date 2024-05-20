import winim/lean

import utils/[stackstr]
import instance , undefined_ref

proc messageBoxTest() {.exportc: "msgBoxTest", dynlib.} = 
  var 
    s1 {.stackStringA.} = "Here is a test"
    s2 {.stackStringA.} = "Here is also a test"
  discard ninst.Win32.MessageBoxA(cast[HWND](0), cast[LPCSTR](s1[0].addr), cast[LPCSTR](s2[0].addr), MB_OK.UINT)


proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReason: LPVOID): BOOL {.stdcall, exportc:"DLLMain", dynlib.} =
  discard ninst.init()

  if fdwReason == DLL_PROCESS_ATTACH:
    messageBoxTest()
  return true




