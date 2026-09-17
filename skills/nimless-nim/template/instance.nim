## nimless NIMLESS_INSTANCE - trimmed to the kernel32 + user32 functions the
## template's PRINTA (utils/stdio.nim) needs. Add fields to MODULES/WIN32 and a
## getFuncPtr call in init for every Windows API you use; see reference/runtime.md.
import std/[macros]
import winim

import utils/[gpa, gmh, hash, stackstr]

type
  MODULES* {.pure.} = object
    kernel32*: HMODULE
    user32*:   HMODULE


  WIN32* {.pure.} = object
    # KERNEL32.DLL
    ExitProcess*:    type(winbase.ExitProcess)
    GetProcessHeap*: type(GetProcessHeap)
    GetStdHandle*:   type(GetStdHandle)
    LoadLibraryA*:   type(LoadLibraryA)
    LocalAlloc*:     type(LocalAlloc)
    LocalFree*:      type(winbase.LocalFree)
    WriteConsoleA*:  type(WriteConsoleA)

    # USER32.DLL
    wsprintfA*:      type(winuser.wsprintfA)


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

    getFuncPtr(ninst.Module.kernel32, ninst.Win32.ExitProcess)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetProcessHeap)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.GetStdHandle)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LocalAlloc)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LocalFree)
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.WriteConsoleA)
  else: return false

  # Load USER32.dll
  var user32 {.stackStringA.} = "user32.dll"
  ninst.Module.user32 = ninst.Win32.LoadLibraryA(cast[cstring](user32[0].addr))
  if ninst.Module.user32 != 0:
    getFuncPtr(ninst.Module.user32, ninst.Win32.wsprintfA)
  else: return false

  ninst.IsInitialized = true

  return true
