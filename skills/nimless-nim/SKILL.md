---
name: nimless-nim
description: "How to write Nim that compiles without the Nim runtime (NRT) and without the C runtime (CRT): Windows x64 mingw/winim targets producing 3-6 KB stage-0 PEs and PIC shellcode. Covers the inverted assumptions (you are the runtime: no GC, IO, exceptions, string/seq, or IAT), the nim.cfg flag core and entry-point contract, hash-based PEB/EAT resolution plus the NIMLESS_INSTANCE function-pointer pattern, compile-time stack strings and payload encryption, direct syscalls via HellsGate, manual memory and threading, obfuscation techniques, and the residual-artifact gotchas (Dl_<n>_ symbols, forwarded exports, PreMain stripping)."
---

# Writing nimless Nim

**Use this when** the task is to write, port, or debug Nim that must run with neither the Nim
runtime (NRT) nor the C runtime (CRT): stage-0 loaders, kilobyte-scale PEs, position-independent
shellcode, or payloads that must not carry Nim's runtime fingerprint. The prior this pack inverts is
the important part - you are not writing Nim *with* a smaller library, you are writing C-shaped Nim
*as* the runtime. Mechanism lives in `reference/`; a working skeleton lives in `template/` and is
verified to build and run (Section 15).

- `reference/build.md` - flags, what removes the runtimes, entry override, `script.ld`, EXE vs DLL,
  stripping, optimization, the DLL size recipe, how to check a build, cross-compiling.
- `reference/runtime.md` - hash, `gmh`, `gpa`, forwarded exports, `NIMLESS_INSTANCE`, the entry
  contract, `undefined_ref.nim`, HellsGate, pointer/memory idioms.
- `reference/strings.md` - stack strings, the four obfuscation generations, `xorStackString`,
  compile-time payload encryption, bcrypt decryption with `goto`, stdlib replacement.
- `template/` - a minimal nimless EXE (`main.nim`, `instance.nim`, `utils/`, `nim.cfg`,
  `script.ld`) that cross-compiles to a zero-import PE.

## 1. What nimless actually is

The delivered artifact is a Windows x64 PE that names no DLL in its import directory and carries no
Nim initialization. **Measured** on this pack's toolchain (nim 2.2.10, winim 4.0.0, gcc 13-win32,
wine 9.0): the template builds to **4 608 bytes** with 5 sections (`.text` 0x470, `.data` 0x60,
`.rdata` 0x10, `.idata` 0x18, `.reloc` 0xc), **zero** import entries, entry at offset 0 of `.text`,
and runs to completion with exit code 42. The deck's own numbers - "~3-6 kb; stage 0
payloads/loaders", "3kb binary (if compiled with strip)", "Fewer imports from KERNEL32.dll (56 ->
12)" - are from nim 2.0.2/2.0.4 and gcc 11.1.0 and are not reproduced here; the property that
matters is the zero-import artifact, not the exact byte count.

The price, in the deck's words: "Drastically different way of writing in Nim - Manual memory and
thread management - Limit types". Everything the runtime used to do becomes your code.

Why remove the runtime at all, per the deck's `0x01` slide:

> - Nim runtime is flagged by a lot of AVs
> - Write Nim programs kilobytes in size (~3-6 kb; stage 0 payloads/loaders)
> - Write PIC shellcode
> - Torqued Maldev

The runtime is not deleted from the compiler's output - it is *bypassed* (`--noMain:on` plus a
linker entry override) and then *garbage collected* (`-ffunction-sections`, `-fdata-sections`,
`-Wl,--gc-sections`). See `reference/build.md` Section 2.

## 2. The laws

Each of these is a prior to invert before you start typing, with the failure it prevents.

1. **There is no runtime.** No GC, no bounds/overflow checks, no exceptions or unwinding, no IO, no
   threads, no `string`/`seq` as runtime values. `--noMain:on` also turns off IO, so `echo` and
   `debugecho` do not work (repo comment). Failing to internalize this produces code that compiles
   under a normal config and does not link under this one.
2. **Nothing comes from the import table.** Every Windows API address is found by hand - PEB walk,
   export-table walk, hash - or it does not exist. A single direct winim call leaves a `Dl_<n>_`
   symbol in `.data` that nothing will ever fill (Section 6).
3. **Every literal you want hidden is built at runtime or encrypted at compile time.** A Nim
   `string`/`cstring` literal lands in `.data` verbatim (deck: "Nim string / cstring declarations end
   up in .data section").
4. **Entry is a two-symbol contract.** An `exportc` symbol plus a linker `-e` flag. `main` is a
   plain callee, not an entry point, and nothing returns to it.
5. **Memory is explicit.** Allocate, validate, track, free. There is no owner and no drop; failures
   are silent until they are exploitable.
6. **Compile time is where the heavy lifting goes.** `static`, `staticExec`, `staticRead`,
   `static(...)` and macros run on your machine; runtime code stays small and dumb.
7. **You reimplement every library function you touch.** There is no stdlib floor under you - not
   `strlen`, not `memcpy` (Nim's own `copyMem` becomes a loop), not `printf`.

## 3. Build contract

Summarized here; `reference/build.md` is authoritative and annotates every flag.

The core, which is the whole contract: `--define:danger` (no checks), `--mm:none` (no GC/allocator),
`--threads:off`, `--cpu:amd64`, `--opt:none`, `--noMain:on`, `--define:nimNoLibc` (no MSVCRT),
`--define:noRes`, `--nimcache:"./cache/$projectname"`; C flags `-masm=intel -Os -nostdlib
-nostartfiles -ffunction-sections -fdata-sections -fno-jump-tables -fno-exceptions
-fno-asynchronous-unwind-tables -fmerge-all-constants -s`; linker flags `-Wl,-estart -nostdlib
-Wl,--gc-sections -Wl,-s`.

- `-ffunction-sections` + `-fdata-sections` + `-Wl,--gc-sections` is the mechanism that deletes
  NRT/CRT code: "This is required, it allows the linker to garbage collect functions that aren't
  used (aka functions in the NRT and CRT)" (`src/0x10` cfg comment).
- `-nostdlib` must be passed to **both** the compiler and the linker (the config says so in place).
- Cross-compiling from Linux is one flag: add `-d:mingw` (root `README.md`). The template keeps it
  out of `nim.cfg` on purpose.
- **Flag order [measured]:** options must precede the project file. `nim c -d:mingw -o:out.exe
  main.nim` works; putting `-o:` after `main.nim` fails with "arguments can only be given if the
  '--run' option is selected".
- `--t:"-fno-builtin"` is **required** on gcc 13: without it, gcc turns `gpa.nim`'s `strlenA` byte
  loop into a call to libc `strlen` and the link fails. This is the general rule for a CRT-less
  target - never let gcc expand your code into a library that will not be linked.
- `script.ld` is for *extraction*, not execution: **[measured]** a `-T`-scripted build of the
  template is rejected by the loader ("Bad EXE format"), and `-T` does not even move `.text` for a
  default build (mingw already puts it at `0x140001000`). Its value is a deterministic section
  layout - and for the shellcode workflow the base-0 recipe gives `.text` at RVA 0 with zero
  relocations inside it. Build and test without `-T`; add it only when you lift `.text` out.

## 4. Entry-point contract

`Main` is a plain `{.exportc.}` proc; `start` is the real entry, pinned to the beginning of `.text`
so it is trivially extractable, aligns the stack, calls `Main`, and returns. From `template/`:

```nim
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
```

- `codegenDecl: "__attribute__((section (\".text\"))) $# $#$#"` is what forces `.text` placement -
  not the linker script.
- `{.asmNoStackframe.}` suppresses Nim's prologue; the `and rsp, 0xfffffffffffffff0` / `sub rsp,
  0x10` you wrote is what runs.
- `--l:"-Wl,-estart"` points the PE header at the symbol; `exportc` must match exactly.
- `when isMainModule: start()` is how the body is emitted under `--noMain:on`.
- Terminate with `ninst.Win32.ExitProcess(code)` - the deck's 0x03 note: "Does not exit cleanly:
  Required to call ExitProcess". A DLL uses
  `DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReason: LPVOID): BOOL {.stdcall,
  exportc:"DLLMain", dynlib.}` with `--l:"-Wl,-eDLLMain"` (`reference/runtime.md` Section 6).
- Every file carrying `asm` also carries `{.passC:"-masm=intel".}`.

## 5. Nothing comes from the import table

Three functions, in order: `hashStrA`/`hashStrW` (a seeded djb2, `h*33+c` in `uint32`), `gmh`
(module handle by walking `PEB->Ldr.InMemoryOrderModuleList` from `gs:[0x60]`), `gpa` /
`getProcAddressHash` (export address by walking `DataDirectory[0]`'s
`AddressOfNames`/`AddressOfFunctions`/`AddressOfNameOrdinals`). All are in `reference/runtime.md`.

Two rules that decide whether your build works:

- **`gmh` has two generations with different caller contracts.** `0x04`-`0x10` hash the wide
  `FullDllName` and need the exact PEB string (case-sensitive, extension included):
  `gmh("KERNEL32.DLL")`. `0x11`/`0x12` lowercase the name and compare incrementally, needing a
  lowercase **prefix** of the base name: `gmh("kernel32")`. Passing the wrong form returns a null
  handle, not an error. **[measured]** under wine (lowercase PEB names) `gmh("ntdll.dll")` resolves
  in generation 1 while `gmh("KERNEL32.DLL")` does not; in generation 2 `"kernel32"`, `"kernel"` and
  even `"k"` resolve, but `"kernel32.d"` and `"KERNEL32.DLL"` do not. Never pass a short prefix -
  the first module that matches wins.
- **Forwarded exports must be handled** or `HeapAlloc`-class functions come back null: the export's
  RVA points at a `"DLL.Function"` string inside the export directory, and `gpa` must detect that by
  range test, `LoadLibraryA` the named module and recurse (deck 0x05: "Q: ...but HeapAlloc doesn't
  work? A: Forwarded Functions"). Resolve `LoadLibraryA` first in `init`.

**Diagnostic.** If a build links but crashes, or you see a `.data` symbol named like
`Dl_1543506853_`, you called a Windows API directly through winim instead of through the instance.
The 0x12 README: "If there is a variable in the data section named something like `Dl_1543506853_`
(ie when looking at the disassembly), this means the program is trying to call a WinAPI function
directly (using winim). This would have relied on the Nim runtime to retrieve the address of that
function; reminder that the operator must do that."

**[measured]** what that failure actually looks like: adding one direct `GetProcessHeap()` call to
the template still *links*, leaves `Dl_1543506257_` (null) in `.data`, pulls in an undefined
`atexit`, grows the binary from 4 608 to 15 231 bytes, and then page-faults at RIP `0` on the call -
`rax` holding the address of the empty `Dl_` slot. Find it with an **unstripped** build:
`x86_64-w64-mingw32-nm out.exe | grep Dl_` (with `-s` there are no symbols to grep).

## 6. The instance is your stdlib

`NIMLESS_INSTANCE` holds one `HMODULE` per module and one typed function pointer per API, so the PEB
and export walks happen once instead of at every call site. The 0x11 README's framing:

> One probable problem we have with writing nimless nim is the reuse of our `getModuleHandle` and
> `getProcAddress` replacements. We might be calling multiple functions throughout our program and
> it's wasteful to always be accessing the `PEB` for the module handle and resolving pointers to
> functions. One solution to this is to create an instance to hold our handles and function pointers,
> so we aren't needlessly calling them over and over again. It is what many C2 frameworks do, such as
> Havoc.

Shape: `MODULES` (handles), `WIN32`/`BCRYPT`-style objects whose fields are `type(SomeApiProc)`, a
`getFuncPtr` macro that assigns each field from `getProcAddressHash`, and `init(ninst): bool`. Call
sites become `ninst.Win32.ExitProcess(42)`.

Three caveats, all covered in `reference/runtime.md` Section 5:

- **Winim ambiguity:** "If winim has multiple definitions for one function (I.e: `ExitProcess`), you
  must define which file of winim to import from... Alternatively, you can type declare the
  functions yourself." Use `type(winbase.ExitProcess)`, `type(winbase.LocalFree)`, etc.
- **Anything winim does not type, you declare.** The instance pattern needs the winim *type*, not
  winim itself.
- **`getFuncPtr` is positional about its arguments [measured].** Its first argument must be a
  `ninst.Module.<field>` path (`DotExpr` of `DotExpr`); a bare handle variable fails with
  `Error: cannot get child of node kind: nnkIdent`. Put every handle in `MODULES`, even one you
  never read again.

## 7. Strings and secrets

The rule first: a Nim `string` is a compile-time construct only. Runtime string values are `cstring`,
`pointer`, or `ptr uint16`, plus a length where the API needs one. See `reference/strings.md`.

- `var s {.stackStringA.} = "literal"` (or `stackStringW`) builds `array[len+1, byte|uint16]` on the
  stack via per-character stores. Consume it with `cast[cstring](s[0].addr)` or `CPTR(s)` /
  `CWPTR(s)`; `s.len` is the count including the NUL, which is what buffer-size arguments want.
  **[measured]** the template prints a stack address for a `{.stackStringA.}` local.
- Never build a Nim **`string` value** - a `let`/`var` copy of a literal, `&` concatenation, `$`,
  `addChar`. The copy (`copyString`) is an allocation, and its presence in `Main` is what predicts a
  `-nostdlib` link failure on `fwrite`/`exit`/`VirtualAlloc`; a `const` indexed in place, a
  `const array[N, byte]` and `"lit".cstring` all link. Measured chain and the spelling table are in
  `reference/strings.md` Section 1.
- Four degrees of hiding, in increasing order of effort: plain stores (0x11), single-byte xor with a
  compile-time random key (0x09), a rolling `rotateRightBits(i)` key with `always_inline` cleanup
  (0x10), and shuffled store order (0x12). 0x11 and 0x12 ship *unencrypted* macros; only 0x09/0x10
  encrypt. The deck's reason for preferring a scalar key: "A multibyte xor key was attempted, but
  kept getting allocated in .rdata; which is fine, but we are trying to avoid unnecessary usage in
  the data section."
- Standing literals that must be decrypted at run time use `xorStackString(buf, key)` over a
  ciphertext in the source (0x05/0x06), optionally with junk `asm` bytes in the loop (0x07).
- Payloads use `staticRead` (cleartext in the image) or
  `var (buf, key, iv) = static(encryptAes(slurp("payload")))` with `nimcrypto` at compile time. Be
  honest about the guarantee - the README: "The payload, key, and iv are held within the executable,
  so it would be trivial to RE."
- Compile-time encryption is undone at run time by `installAesDecryption` through the bcrypt entries
  of the instance.
- Cleanup paths use `goto`/`label` from `utils/goto.nim` (`{.emit.}`-based), because
  `-fno-exceptions` and no runtime mean there is no `defer` and no unwinding.

## 8. You reimplement every library you touch

There is no floor under you. What the repo had to write:

- `stringh.nim` (`wcslen`, `wcsncmp`, `cmpStrAToStrW`) and `str.nim`/`strlenA` for string work.
- `PRINTA`/`dumpHex` in `utils/stdio.nim` for output - `wsprintfA` + `LocalAlloc` + `WriteConsoleA`
  through the instance, compiled in only under `-d:malDebug`.
- `undefined_ref.nim` for the DLL link: no-op `exportc` stubs (`fwrite`, `fflush`, `exit`,
  `__imp_VirtualAlloc`, `_setjmp`, ...) that satisfy the linker without adding an import.

The 0x12 porting rule: "Any use of the standard library will need to be redefined." If a technique
needs `memcpy`, write the loop; Nim's own `copyMem`/`zeroMem` already are loops under
`--define:nimNoLibc`.

## 9. Memory and threads

- Allocation is explicit and paired: `LocalAlloc`/`LocalFree` (small buffers, `LPTR` = fixed +
  zeroed), `HeapAlloc`/`HeapFree` on `GetProcessHeap()` with `HEAP_ZERO_MEMORY` (when an API tells
  you the size), and `VirtualAllocEx`/`NtAllocateVirtualMemory` for executable memory. Validate
  every allocation, free on every path, and give each function one cleanup block
  (`reference/runtime.md` Section 9).
- Buffers are fixed arrays; the element count is usually the length argument
  (`szPath: array[MAX_PATH*2, WCHAR]` for `GetModuleFileNameW`).
- `ptr UncheckedArray[T]` is the universal view; address arithmetic is `cast[int]`, never pointer
  math.
- **There is no `CreateThread`.** `--threads:off` removes what would back it. Use `NtCreateThreadEx`
  through the HellsGate table, or skip thread creation entirely and hijack an existing thread pool
  (`src/0x12 - nimless_DLL/nimpool/`).

## 10. Direct syscalls when userland is hooked

When `gmh`/`gpa` cannot be trusted, issue the syscall yourself. The shape (0x06):

```nim
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

`VX_TABLE` holds `(pAddress, dwHash, wSystemCall)` per syscall; `initHG` fills it by finding the
`ntdll` export by hash and extracting the SSN from the stub bytes `4c 8b d1 b8` (`mov r10, rcx; mov
rcx, <ssn>`, read at `+4`/`+5`) rather than hard-coding numbers, which are build-specific. The
4-edit recipe for adding a syscall: `VX_TABLE` entry, `initHG` hash + lookup, `HellsGate` +
`HellsDescent` call site, and the caller that needs it.

Three defects in the shipped code, covered in `reference/runtime.md` Section 8. The `0f 05` "overshot"
guard compared the same byte against both values and so never fired; it is fixed in this repo's
`0x06`/`0x07` (`p[j] == 0x0f and p[j + 1] == 0x05`), and it now refuses a reshaped stub the way it was
meant to - **[measured]**, see the reference. Two are still worth fixing rather than copying:
`getVxTableEntry` returns `true` unconditionally, so an unmatched hash yields `HellsGate(0)` (syscall
0 is `NtAccessCheck` - a real service, silently issued), and the single global `wSystemCall` makes the
mechanism single-threaded by construction.

## 11. Obfuscation raises cost, not safety

The 0x07 example is a toolkit of static-analysis annoyances, and it should be framed that way - it
buys time, not safety:

- Compute the PEB pointer instead of using the literal: `xor rax,rax / mov rax,0x10 / imul rax,rax,6
  / mov rax, qword ptr gs:[rax]` (still `gs:[0x60]`, no displacement for a scanner to match).
- Break up the PE-header checks with arithmetic and opaque guards: `e_magic + 420 !=
  IMAGE_DOS_SIGNATURE + 420`, plus `testJmpFail`/`jmp FAILURE` blocks that make every intermediate
  pointer look checked (the deck's own description: "some dumb stuff to trick capa into thinking we
  aren't parsing a PE header").
- Anti-debug via `NtQueryInformationProcess(ProcessDebugFlags = 31)` (the mechanism available once
  HellsGate is in place, per the deck's 0x07 slides).
- Junk `asm` bytes inside hot loops (`0x07/utils/enc.nim`).
- `{.noRewrite.}` around `getAst`-injected code so Nim cannot rewrite it.

The deck notes the limits directly: the xor'd strings are "Almost APT level encryption, just use
imagination. (aka, floss finds this)", and "Various optimization levels (`-O0`, `-O1`, ...) yields
different results" - so obfuscation results are toolchain- and level-dependent.

## 12. Gotchas that waste hours

- **`Dl_<n>_` in `.data`** - a direct winim call. It links, then jumps to a null pointer. Needs an
  unstripped build to see. (Section 5)
- **Forwarded exports** - `HeapAlloc`-class functions resolve to null without the forwarding branch;
  keep `.text`'s `LoadLibraryA` resolution first in `init`.
- **`getProcAddressHash` iterates `NumberOfFunctions` but indexes `AddressOfNames`**, so modules with
  ordinal-only exports (ntdll) get out-of-range name reads; a garbage pointer can hash to a match.
- **Generation-2 `gmh` is prefix-based and terminates at the first dot** - `"kernel32.d"` cannot
  match, `"k"` matches the wrong module.
- **`getFuncPtr` requires a `ninst.Module.<x>` argument**, not a local handle.
- **DLL builds keep `NimMain`/`PreMain`** and come out ~44 KB until you truncate the generated C at
  `N_LIB_PRIVATE void PreMainInner(void) {` (44 257 -> 5 120 bytes in the repo) - `reference/build.md`
  Section 8, automated in `0x12/make_dll.bat`.
- **gcc 13 rewrites your loops into libc calls** unless `-fno-builtin` is set (`undefined reference to
  strlen`).
- **`script.ld` builds do not load** - they are extraction artifacts; and `-T` alone does not move
  `.text`.
- **`--t:"-s"` never reaches the compile line**; stripping is `-Wl,-s`. Keep both, know which works.
- **The nimcache json is named after the output**: `-o:verify_debug.exe` gives
  `cache/main/verify_debug.json`, not `main.json`.
- **`PRINTA` does not check `IsInitialized`** - printing before a successful `init` jumps through
  null.
- **A `-d:malDebug` build needs a real console.** **[measured]** with stdout piped, `WriteConsoleA`
  produces nothing (the exit code is still correct); run it attached to a terminal.
- **A Nim `string` value breaks the link.** A `let`/`var` string variable copies its literal
  (`copyString`) - an allocation - which makes `rawAlloc`/`osAllocPages` and the OOM reporter
  reachable, and those call `fwrite`/`fflush`/`strlen`/`exit`/`VirtualAlloc`. `-nostdlib` then fails
  on exactly that list. Use a `const array[N, byte]`, index a `const string`, take `.cstring`, or use
  `{.stackStringA.}`. **[measured]**: the `copyString` call site predicts the failure across five
  spellings (`reference/strings.md` Section 1).
- **Debug workflow:** compile with `-d:malDebug` (the `when` is compiled out entirely otherwise), run
  the unstripped build, and read the real flags out of `cache/<project>/<output>.json`.

## 13. Porting an existing Nim program

The 0x12 README's checklist, verbatim:

1. Remove any uses of echo; we can replace this with PRINTA if we desire.
2. Change uses of the WinAPI to our instance; ex: `:%s/<WinApiFunctionName>/ninst.Win32.WinApiFunctionName/g`
3. Any use of the standard library will need to be redefined. This is done in `utils/stdlib/stringh.nim`. An example of this is `wcslen`:
4. Changing all string definitions to `stackStringA` and `stackStringW` pragmas, then passing in the pointer of those to functions.

Then close the loop the same way any build is verified: no `Dl_` symbols in an unstripped build, zero
`DLL Name` entries in the import directory, entry at the head of `.text`, expected exit code, and a
size in kilobytes. `reference/build.md` Section 9 has the exact commands.

Practical ordering: get the two-symbol entry + `ExitProcess` working with no instance at all first,
then add the instance, then convert call sites, then convert literals to stack strings, and only then
add encryption. Each step is independently verifiable with the command in Section 14.

## 14. Where to start

Copy `template/` and build it before writing anything:

```bash
cd template
nim c -d:mingw -d:malDebug -o:verify_debug.exe main.nim   # PRINTA compiled in
nim c -d:mingw -o:verify_stripped.exe main.nim            # release, stripped

x86_64-w64-mingw32-objdump -p verify_stripped.exe | grep -A2 "DLL Name"   # expect nothing
x86_64-w64-mingw32-objdump -h verify_stripped.exe                         # .text at 0x140001000
x86_64-w64-mingw32-objdump -d verify_stripped.exe | sed -n '1,12p'        # start stub first
WINEDEBUG=-all wine ./verify_debug.exe                                    # attach a real console
echo "exit=$?"                                                            # expect 42
```

`nimble install winim` is the only prerequisite beyond a mingw gcc; winim is the repo's typing source
(and `reference/runtime.md` Section 5 explains how to run without it, by declaring the types you
need). The template's `nim.cfg` is the canonical 0x11 config minus the Windows-subsystem flag (so
`PRINTA` has a console to write to) and plus `-fno-builtin` for gcc 13; add
`--l:"-Wl,-subsystem,windows"` back for a real payload.

## 15. Provenance

- Repo: `m4ul3r/writing_nimless` - <https://github.com/m4ul3r/writing_nimless> (the source of every
  file quoted in `reference/`, and of this pack's `template/`).
- Talk: "Writing Nimless Nim - Writing Offensive Tools Using Nim Without the Nim Runtime", Tyler
  Randolph (m4ul3r), BSIDESKC 2024. The deck ships in this repo as `Writing Nimless nim.pdf` (47
  slides); video: <http://www.youtube.com/watch?v=EXX3HmCG3pw>.
- Previous lecture in the series: `us-cyber-team/nim_for_hackers2` -
  <https://github.com/us-cyber-team/nim_for_hackers2>.
- The `nim.cfg` is not original to this repo: the deck says "We use a nim.cfg that is modified config
  from Bitmancer repo" and, in the config section, "It's already heavily documented from zimawhit3's
  Bitmancer."
- `HellsGate`/`HellsDescent` implement the technique commonly called HellsGate - getting a syscall
  number by parsing the `ntdll` stub at run time instead of hard-coding it. The repo does not cite a
  source for it; the syscall-injection code it is used with is the author's own
  `nim/thread_pool_injection` (`src/0x12 - nimless_DLL/nimpool/` says "Copy pasta from:
  https://github.com/m4ul3r/malware/tree/main/nim/thread_pool_injection").
- `NIMLESS_INSTANCE` is credited in the 0x11 README to what C2 frameworks such as
  <https://github.com/HavocFramework/Havoc> do.

Example -> capability map, for going straight to a source:

| Example | Demonstrates |
|---|---|
| `0x02 - hw_runtime` | the baseline: what the runtime costs |
| `0x03 - no_runtime_basic` | runtime removed, `-eNimMainModule`, hard-linked kernel32/user32 |
| `0x04 - self_delete` | `gmh`/`gpa`/hash/stackstr utilities, `-estart`, entry at head of `.text`, `script.ld` |
| `0x05 - heapalloc_ff` | forwarded exports (`HeapAlloc`), the typed `gpa` template |
| `0x06 - self_injection_loader` | HellsGate direct syscalls, `xorStackString`, payload download |
| `0x07 - self_injection_loader_obfuscated` | PEB/PE-header obfuscation, opaque jumps, anti-debug, junk asm |
| `0x08 - reverse_shell` | the payload used for the demo, plus `deleteSelf` |
| `0x09 - improving_stackStr` | stack-string generation 2: compile-time single-byte xor key |
| `0x10 - improving_stackStr2` | generation 3: rolling key, `always_inline` cleanup |
| `0x11 - simple_instance` | `NIMLESS_INSTANCE`, the lowercase `gmh`, `PRINTA`/`dumpHex` |
| `0x12 - nimless_DLL` | nimless DLL + threadpool injection + compile-time AES and runtime bcrypt |
