# 0x12 - nimless DLL

### Creating a Simple DLL

In all previous examples, only PE executables have been used. It is possible to write nimless DLL files in a similar way that we use to create PE executables, but with a little more manual work. First off we can try to create a simple DLL in nim and compile it with out nimless `nim.cfg`. We use an instance to handle functions the same way we did for `0x11 - simple_instance`.

```nim
# initial `main.nim`
import winim/lean

import utils/[stackstr]
import instance 

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
```

When this is compiled, you'll see a hidious error log mentioning undefined reference to `__imp___acrt_iob_func`, `fwrite`, `fflush`, ... ect. How we go about this is do redefine these functions to do nothing, this is done in `undefined_ref.nim`. We use the `exportc` pragma to tell the compiler and the linker that the function exists in this file, and future object. These are functions that we won't be using or if we are using, we would define ourselves.

```nim
# `undefined_ref.nim`
proc nothing1*() {.exportc: "__imp___acrt_iob_func".} = discard
proc nothing2*() {.exportc: "fwrite".} = discard
proc nothing3*() {.exportc: "fflush".} = discard
proc nothing4*() {.exportc: "exit".} = discard
proc nothing5*() {.exportc: "__imp_VirtualAlloc".} = discard
proc nothing6*() {.exportc: "_setjmp".} = discard
proc nothing7*() {.exportc: "signal".} = discard
proc nothing8*() {.exportc: "__imp__fileno".} = discard
proc nothing9*() {.exportc: "__imp__setmode".} = discard
proc nothing10*() {.exportc: "__imp_longjmp".} = discard
```

Next we have a few additions to our `nim.cfg`.

```
## Define DLL
--app=lib

## Linker flags
## Tell to link to DLLMain
--l:"-Wl,-eDLLMain"

# If we need to define a relocation table, we can enable this flag
## Allow relocation table
#--l:"-Wl,--dynamicbase"
```

We can compile it as it and see that it is `44kb` in size. The reason for this is that `NimMain` function is still included in the resulting DLL. 

```
PS C:\Users\user\Desktop\writing_nimless\src\0x12 - nimless_DLL> nim c .\main.nim
Hint: used config file 'C:\Users\user\.choosenim\toolchains\nim-2.0.4\config\nim.cfg' [Conf]
Hint: used config file 'C:\Users\user\.choosenim\toolchains\nim-2.0.4\config\config.nims' [Conf]
Hint: used config file 'C:\Users\user\Desktop\writing_nimless\src\0x12 - nimless_DLL\nim.cfg' [Conf]
............................................
C:\Users\user\.choosenim\toolchains\nim-2.0.4\lib\system\mm\none.nim(3, 12) Warning: nogc in a library context may not work [User]
...................................................................................................................
C:\Users\user\Desktop\writing_nimless\src\0x12 - nimless_DLL\main.nim(4, 19) Warning: imported and not used: 'undefined_ref' [UnusedImport]
CC: undefined_ref.nim
Hint:  [Link]
Hint: mm: none; opt: none (DEBUG BUILD, `-d:release` generates faster code); options: -d:danger
160348 lines; 3.187s; 319.727MiB peakmem; proj: C:\Users\user\Desktop\writing_nimless\src\0x12 - nimless_DLL\main.nim; out: C:\Users\user\Desktop\writing_nimless\src\0x12 - nimless_DLL\main.dll [SuccessX]
PS C:\Users\user\Desktop\writing_nimless\src\0x12 - nimless_DLL> dir main.dll


    Directory: C:\Users\user\Desktop\writing_nimless\src\0x12 - nimless_DLL


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/19/2024   7:41 PM          44257 main.dll
```

The linker is responsible for garbage collecting functions that are not referenced, but the problem here is that `NimMain` calls `PreMain` and `PreMainInner` which in turn are referenced by other functions. A manual way of resolving this to make our binary smaller is by removing the function from the generated C code. If you call `nim c --genscript .\main.nim`, this will generate a `compile_main.bat` in the `cache\main` directory. We can edit `@mmain.nim.c` to delete `PreMainInner`, `PreMain`, `NimMainInner`, `NimMain`, and `NimMainModule`. 


```nim
PS C:\Users\user\Desktop\writing_nimless\src\0x12 - nimless_DLL\cache\main> .\compile_main.bat

<snip -> compile and link output > 

PS C:\Users\user\Desktop\writing_nimless\src\0x12 - nimless_DLL\cache\main> dir .\main.dll


    Directory: C:\Users\user\Desktop\writing_nimless\src\0x12 - nimless_DLL\cache\main


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/19/2024   7:53 PM           5120 main.dll
```

### Thread pool injection example




### Notes

If there is a variable in the data section named something like `Dl_1543506853_`, this means the program is trying to call a WinAPI function directly (using winim). This would have relied on the Nim runtime to retrieve the address of that function; reminder that the operator must do that.  