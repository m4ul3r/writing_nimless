# Build contract - flags, entry override, section layout

> **Provenance.** This file is derived from the repo `m4ul3r/writing_nimless`: the per-example
> `nim.cfg` files (`src/0x03`, `0x04`, `0x05`, `0x06`, `0x10`, `0x11`, `0x12`), the three
> `script.ld` variants, and the deck's `0x12 - nim.cfg` / `0x12 - damn, what else?` slides.
> The repo `README.md` is the only source for the cross-compilation rule.
>
> Everything marked **[measured]** was executed in this environment:
> nim 2.2.10, winim 4.0.0, `x86_64-w64-mingw32-gcc (GCC) 13-win32`, binutils ld 2.41, wine 9.0.
> Numbers the deck quotes (~3 KB binaries, 56 -> 12 imports) come from the author's
> toolchain (nim 2.0.2/2.0.4, gcc 11.1.0) and are not reproduced here.

Two spellings you need first, because they appear nowhere in long form in the repo:

| Short | Long | Meaning |
|---|---|---|
| `--t:` | `--passC` | flag handed to the C compiler (`gcc`) for every generated `.c` |
| `--l:` | `--passL` | flag handed to the linker command |

Some flags must be given to **both**; that duplication is deliberate and is called out below.

## 1. The flag core

`template/nim.cfg` is `src/0x11 - simple_instance/nim.cfg` (the canonical hardened EXE config)
with three documented deltas - no `-subsystem,windows`, the non-functional function-alignment
block removed, and `--t:"-fno-builtin"` added for gcc 13 (Section 7). `--define:malDebug` stays
commented out so debug output is opt-in on the command line.

```ini
## Nim Flags
## Standard Flags
--define:danger 
--mm:none 
--threads:off 
--cpu:amd64
--opt:none

## Set the cache directory
--nimcache:"./cache/$projectname"

## Turn off main procedure generation, that will be set with a linker flag to NimMainModule 
--noMain:on

## Use Nim's routines to prevent linking to MSVCRT
--define:nimNoLibc 

## Turn off Winim's embedded resource
--define:noRes 

# Get debug output
# --define:malDebug

## GCC flags 
## Standard Flags
--t:"-masm=intel"
--t:"-Os"

## Never let gcc rewrite our own loops into libc calls: with no CRT there is no
## strlen/memcpy to link against. gcc 13 recognises the strlenA byte loop in
## utils/gpa.nim as `strlen` and emits a call to it, which fails the link with
## `undefined reference to strlen`; the deck's gcc 11 did not do this.
--t:"-fno-builtin"

# Strip debugging information
--t:"-s"

## Turn off MingW's startup code & dynamically linked libraries (Kernel32 & MSVCRT)
## This is the equivalent of using: -nodefaultlibs -nostartfiles
--t:"-nostdlib"
--t:"-nostartfiles"

## Place functions & data in their own sections, this allows for our linker to
## garbage collect efficiently and reduce the code size.
--t:"-ffunction-sections"
--t:"-fdata-sections"

## Allow the use of case statements for cleaner code
--t:"-fno-jump-tables"

## Turn off Exceptions
--t:"-fno-exceptions"

## Suppress generation of stack unwinding tables
--t:"-fno-asynchronous-unwind-tables"

## Merge identical constants and variables to reduce code size
--t:"-fmerge-all-constants"

## Linker flags 
##------------------------------------
## Bypass all of Nim's initialization procedures, there is no GC so they aren't needed.
## This also turns off IO, so echo/debugecho will not work with this turned on.
--l:"-Wl,-estart"

## This needs to be passed to the compiler AND the linker...
## Reference: http://www.independent-software.com/linking-a-flat-binary-from-c-with-mingw.html
--l:"-nostdlib"

## Garbage collect all unused code sections.
--l:"-Wl,--gc-sections"

## Prevent console from opening
## Deliberately NOT set here: the default console subsystem keeps PRINTA's
## WriteConsoleA output visible (STD_OUTPUT_HANDLE only exists for a console).
## Add this back for a real payload:
# --l:"-Wl,-subsystem,windows"

## Strip the executable of all debugging information
--l:"-Wl,-s"
```

That config is the whole contract. Its groups, and what each one mechanically does:

**Nim-level flags**

- `--define:danger` - "We don't need any memory safety or checks" (deck). Turns off range/overflow
  checks, assertions and the `--checks` family.
- `--mm:none` - no GC and no allocator: `new`/`alloc`/`seq`/`string` growth stop being usable.
  This is the single flag that makes "you are the runtime" true.
- `--threads:off` - "Threads are included in the (NRT)" (deck); also keeps the threading runtime
  out of the link.
- `--cpu:amd64` - pin the target to x86-64 rather than trusting host detection.
- `--opt:none` - "Used so it doesn't specify `--opt:speed` or `--opt:size`; therefore we can
  specify optimizations" (deck). Leaves `-O` to you via `--t:`.
- `--noMain:on` - "Turn off main procedure generation, that will be set with a linker flag to
  NimMainModule" (repo comment). Because no `main` is generated and no `NimMain` is called, the
  repo notes the consequence directly: "This also turns off IO, so `echo`/`debugecho` will not
  work with this turned on."
- `--define:nimNoLibc` - "Use Nim's routines to prevent linking to MSVCRT" (repo comment).
  Mechanically, `lib/system/sysmem.nim` and `lib/system/memory.nim` both start with
  `const useLibC = not defined(nimNoLibc)`, so `copyMem`/`zeroMem`/`alloc` compile to Nim-side
  loops instead of `memcpy`/`memset`/`malloc` calls. Without it you get undefined libc references
  at link time.
- `--define:noRes` - "Turn off Winim's embedded resource": winim otherwise attaches a `.res`.
- `--nimcache:"./cache/$projectname"` - keep the generated C and `.o` files next to the project
  where you can read them (Section 9).

**C compiler flags (`--t:`)** - also see Section 2 for *why* these are the ones that delete the
runtimes:

`-masm=intel` (every file carrying inline `asm` in this repo also re-states it with
`{.passC:"-masm=intel".}`), `-Os`, `-nostdlib`, `-nostartfiles`,
`-ffunction-sections`, `-fdata-sections`, `-fno-jump-tables`, `-fno-exceptions`,
`-fno-asynchronous-unwind-tables`, `-fmerge-all-constants`, `-fno-builtin`, `-s`.

The config's own comment on the rationale: "Turn off MingW's startup code & dynamically linked
libraries (Kernel32 & MSVCRT) - This is the equivalent of using: `-nodefaultlibs -nostartfiles`",
and "Place functions & data in their own sections, this allows for our linker to garbage collect
efficiently and reduce the code size." `-fno-jump-tables` is labelled "Allow the use of case
statements for cleaner code": disabling jump tables keeps `case` compiling to compare/branch
chains instead of emitting a table of addresses that would need relocations and space in
`.rdata`.

**Linker flags (`--l:`)** - `-Wl,-estart` (Section 3), `-nostdlib`, `-Wl,--gc-sections`,
`-Wl,-s`. Note the config repeats `-nostdlib` here with the comment "This needs to be passed to
the compiler AND the linker..." and links to
`http://www.independent-software.com/linking-a-flat-binary-from-c-with-mingw.html`.

### The command lines that actually result **[measured]**

`cache/<projectname>/<output>.json` records the exact argv. For the template's debug build:

```
# every generated .c is compiled with:
x86_64-w64-mingw32-gcc -c -w -fmax-errors=3 -mno-ms-bitfields -fno-strict-aliasing \
  -masm=intel -Os -fno-builtin -nostdlib -nostartfiles -ffunction-sections -fdata-sections \
  -fno-jump-tables -fno-exceptions -fno-asynchronous-unwind-tables -fmerge-all-constants \
  -I<...>/nim-2.2.10/lib -I<...>/template -o <...>.o <...>.c

# and linked with:
x86_64-w64-mingw32-gcc -o <out>.exe <...>.o ... \
  -Wl,-estart -nostdlib -Wl,--gc-sections -Wl,-s -Wl,-Bstatic -lpthread
```

Three things to notice, all of which save debugging time:

- Nim injects its own `-w -fmax-errors=3 -mno-ms-bitfields -fno-strict-aliasing` before yours.
- `--t:"-s"` does **not** appear in the compile line (Nim does not forward it); the stripping that
  happens is the link-time `-Wl,-s`. Keep both in the config anyway - the repo does - but know
  which one does the work.
- `-Wl,-Bstatic -lpthread` is appended even with `--threads:off`. It is harmless here: no pthread
  code is emitted, `-nostdlib` precedes it, and the resulting PE has **zero** imports
  **[measured]**.

## 2. What actually removes the runtimes

Three mechanisms, and you need all three:

1. **Bypass, not delete.** `--noMain:on` + `--l:"-Wl,-estart"` means `NimMainModule`, `NimMain`,
   `PreMain` and friends are still *compiled* into the objects but never called, so nothing
   references them.
2. **Make them collectable.** `-ffunction-sections` and `-fdata-sections` put every function and
   every global in its own section. `--l:"-Wl,--gc-sections"` then drops every section nothing
   references. The `src/0x10 - improving_stackStr2/nim.cfg` comment states the purpose exactly:
   "This is required, it allows the linker to garbage collect functions that aren't used (aka
   functions in the NRT and CRT)". Without the section flags, `--gc-sections` has nothing to
   collect and you link the whole runtime.
3. **Remove the CRT's other entry points and helpers.** `-nostdlib` and `-nostartfiles` on both
   the compiler and the linker; `-fno-exceptions` and `-fno-asynchronous-unwind-tables` kill the
   unwinder and `.eh_frame`; `-fmerge-all-constants` collapses duplicate constant pools.

`--define:nimNoLibc` is the one that belongs to the source level rather than the link: it is what
makes Nim's own `copyMem`/`zeroMem` exist as loops instead of calls into MSVCRT.

What survives is what you wrote plus the handful of helpers Nim emits inline (`nimCopyMem`,
`nimZeroMem`, `eqStrings`-free code paths). **[measured]** the template's own `.text` is 0x470
bytes against 0x60 bytes of `.data`.

## 3. Entry-point override

`--l:"-Wl,-e<symbol>"` is what decides which symbol the PE header points at. Three generations in
this repo:

| Example | Override | Entry symbol |
|---|---|---|
| `src/0x03 - no_runtime_basic` | `--l:"-Wl,-eNimMainModule"` | Nim's generated `NimMainModule` |
| `src/0x04` onward | `--l:"-Wl,-estart"` | your own `proc start()` |
| `src/0x12 - nimless_DLL` | `--l:"-Wl,-eDLLMain"` | your own `DllMain` |

Every config from 0x04 on keeps the superseded line as a commented-out reference
(`# --l:"-Wl,-eNimMainModule"`), which is why you see it in every example's cfg.

The 0x03 config is the "generation 1" shape, and it is worth reading in full because it shows what
the override alone does *not* solve - it still has to hard-link kernel32 and user32 through
`--dynlibOverride` + `--passL`:

```ini
## Nim Flags
## Standard Flags
--define:danger 
--mm:none 
--threads:off 
--cpu:amd64
--opt:size

## Set the cache directory
#--nimcache:"./cache/$projectname"

## Turn off main procedure generation, that will be set with a linker flag to NimMainModule 
--noMain:on

## Use Nim's routines to prevent linking to MSVCRT
--define:nimNoLibc 

## Turn off Winim's embedded resource
--define:noRes 

## Link Libraries
--dynlibOverride:kernel32
--passL:"C:\\Windows\\System32\\kernel32.dll"
--dynlibOverride:user32
--passL:"C:\\Windows\\System32\\user32.dll"


## GCC flags 
## Standard Flags
--t:"-masm=intel"
--t:"-Os"

## Function allignment
--t:"-fno-align-functions"
--t:"-flimit-function-alignment"
--t:"-fno-align-labels"
--t:"-fno-align-jumps"

## Turn off MingW's startup code & dynamically linked libraries (Kernel32 & MSVCRT)
## This is the equivalent of using: -nodefaultlibs -nostartfiles
--t:"-nostdlib"

## Place functions & data in their own sections, this allows for our linker to
## garbage collect efficiently and reduce the code size.
--t:"-ffunction-sections"
--t:"-fdata-sections"

## Allow the use of case statements for cleaner code
--t:"-fno-jump-tables"

## Turn off Exceptions
--t:"-fno-exceptions"

## Suppress generation of stack unwinding tables
--t:"-fno-asynchronous-unwind-tables"

## Merge identical constants and variables to reduce code size
--t:"-fmerge-all-constants"

## Linker flags 
##------------------------------------
## Bypass all of Nim's initialization procedures, there is no GC so they aren't needed.
## This also turns off IO, so echo/debugecho will not work with this turned on.
--l:"-Wl,-eNimMainModule"
 
## This needs to be passed to the compiler AND the linker...
## Reference: http://www.independent-software.com/linking-a-flat-binary-from-c-with-mingw.html
--l:"-nostdlib"

## Garbage collect all unused code sections.
--l:"-Wl,--gc-sections"

## Strip the executable of all debugging information
--l:"-Wl,-s"
```

## 4. Section layout and `script.ld`

`script.ld` is a raw GNU ld script handed in with `--l:"-T./script.ld"`. It exists for two
reasons: to pin where the code lands (so the entry is at a known offset in a known section) and to
say which sections exist at all.

The three variants in the repo, verbatim:

```ld
SECTIONS
{
  . = 0x140001000;
  .text : { *(.text) }
  .data : { *(.data) }
}
```

`src/0x06 - self_injection_loader/script.ld` changes only the origin, for the base-0 shellcode:

```ld
SECTIONS
{
  . = 0x0;
  .text : { *(.text) }
  .data : { *(.data) }
}
```

`src/0x07 - self_injection_loader_obfuscated/script.ld` drops the origin entirely:

```ld
SECTIONS
{
  .text : { *(.text) }
  .data : { *(.data) }
}
```

Facts about the scripts, including one that is easy to get wrong:

- **The `.text`-first entry is not the script's doing.** The script places `.text` before `.data`
  because that is the order it lists them in, but what actually guarantees the entry sits at
  offset 0 of `.text` is the `codegenDecl: "__attribute__((section (\".text\"))) $# $#$#"` on
  `start` plus `--l:"-Wl,-estart"`. **[measured]** the disassembly begins at the very first byte
  of `.text` with exactly the `start` prologue.
- The scripts keep `.data` on purpose: the global `ninst` lives there, and the generated code
  reaches it through RIP-relative loads, so the data has to travel with the code.
- No `ENTRY()`, no `/DISCARD/`, no `.rodata`, no `.bss` clause. Orphan sections are placed by ld's
  inference rules after the scripted ones.
- `. = 0x140001000` **matches mingw's default `.text` address**, so adding this script to a
  default build does not move `.text` **[measured]**: it changes which sections exist and their
  order. What moves is `.rdata`/`.data`, and the empty import section disappears.

**[measured]** with `--l:"-T./script.ld"` added to the template's command line, the image shrinks
4608 -> 4096 bytes, drops from 5 sections to 4 (the first build's `.idata` is gone), and places:

```
  0 .text   00000450  0000000140001000
  1 .rdata  00000010  0000000140002000
  2 .data   00000060  0000000140002020
  3 .reloc  0000000c  0000000140003000
```

And the sharp edge: **a scripted image is an extraction artifact, not a runnable PE.**
**[measured]** wine rejects that same binary with `Bad EXE format`. The first structural defect is
that `.data` lands at `0x140002020`, which is not a multiple of the header's
`SectionAlignment = 0x1000`; note that forcing `--l:"-Wl,--section-alignment,0x20"` fixed the
alignment and wine *still* rejected the image, so treat "scripted builds do not load" as the
operating rule rather than as one alignment bug you can patch. Build and test with the script
absent (as the template ships it), and add `-T` only when you are lifting `.text` out.

**[measured]** the base-0 recipe from 0x06 (`--image-base 0x0` plus `. = 0x0`) does produce the
layout the shellcode workflow wants: `.text` at RVA 0, `.rdata` at 0x1000, `.data` at 0x1020, and
**zero relocations inside `.text`** - every data access is RIP-relative
(`mov 0xfd5(%rip),%rcx`). The single relocation in the whole image is one `DIR64` in the data page
at RVA 0x1000. That is the real content of "PIC shellcode": the code is position-independent but
still *depends on* `.rdata`/`.data` being carried along at the same relative offsets, which is
precisely what the script fixes for you.

## 5. EXE vs DLL deltas

`src/0x12 - nimless_DLL/dll_main.cfg` against the EXE config:

```ini
## Nim Flags
## Standard Flags
--define:danger 
--mm:none 
--threads:off 
--cpu:amd64
--opt:none

## Define DLL
--app=lib

## Set the cache directory
--nimcache:"./cache/$projectname"

## Turn off main procedure generation, that will be set with a linker flag to NimMainModule 
--noMain:on

## Use Nim's routines to prevent linking to MSVCRT
--define:nimNoLibc 

## Turn off Winim's embedded resource
--define:noRes 

# Get debug output
# --define:malDebug

## GCC flags 
## Standard Flags
--t:"-masm=intel"
--t:"-Os"

## Function allignment - Does not work
--t:"-flimit-function-alignment"
--t:"-falign-functions=0"
--t:"-falign-labels=0"
--t:"-falign-jumps=0"

# Strip debugging information
--t:"-s"

## Turn off MingW's startup code & dynamically linked libraries (Kernel32 & MSVCRT)
## This is the equivalent of using: -nodefaultlibs -nostartfiles
--t:"-nostdlib"
--t:"-nostartfiles"

## Place functions & data in their own sections, this allows for our linker to
## garbage collect efficiently and reduce the code size.
--t:"-ffunction-sections"
--t:"-fdata-sections"

## Allow the use of case statements for cleaner code
--t:"-fno-jump-tables"

## Turn off Exceptions
--t:"-fno-exceptions"

## Suppress generation of stack unwinding tables
--t:"-fno-asynchronous-unwind-tables"

## Merge identical constants and variables to reduce code size
--t:"-fmerge-all-constants"

## Linker flags 
##------------------------------------
## Bypass all of Nim's initialization procedures, there is no GC so they aren't needed.
## This also turns off IO, so echo/debugecho will not work with this turned on.
--l:"-Wl,-eDLLMain"

## This needs to be passed to the compiler AND the linker...
## Reference: http://www.independent-software.com/linking-a-flat-binary-from-c-with-mingw.html
--l:"-nostdlib"

## Garbage collect all unused code sections.
--l:"-Wl,--gc-sections"

## Print out the sections garbage collected
#--l:"-Wl,--print-gc-sections"

## Allow relocation table
#--l:"-Wl,--dynamicbase"

## Base binary to fit within 64bit
--l:"-Wl,--image-base" 
--l:"-Wl,0x10000000"

## Prevent console from opening
--l:"-Wl,-subsystem,windows"

## Strip the executable of all debugging information
--l:"-Wl,-s"
```

The complete delta list:

- `--app=lib` - emit a DLL.
- `--l:"-Wl,-eDLLMain"` instead of `-estart`.
- `--l:"-Wl,--image-base"` + `--l:"-Wl,0x10000000"` - "Base binary to fit within 64bit".
- `--l:"-Wl,-s"` active (the EXE config leaves strip commented for development).
- `--l:"-Wl,--print-gc-sections"` and `--l:"-Wl,--dynamicbase"` present but commented:
  "Print out the sections garbage collected" and "Allow relocation table".
- Everything else - `--noMain:on`, `--mm:none`, the whole C flag block - is identical.

A DLL additionally needs `undefined_ref.nim` (see `reference/runtime.md` Section 7) and usually the
`PreMain` stripping step (Section 8). `--dynamicbase` is what you uncomment if you want a
relocation table rather than a fixed-base image.

## 6. Stripping

Two flags, two different jobs, and the repo is inconsistent about them on purpose:

- `--t:"-s"` - kept in `0x04`, `0x05`(commented), `0x10`, `0x11`, `0x12`.
- `--l:"-Wl,-s"` - "Strip the executable of all debugging information"; commented out in the
  development-oriented configs (`src/0x12 - nimless_DLL/nim.cfg` has `# --t:"-s"` and
  `# --l:"-Wl,-s"`).

The deck frames it as "Final nim.cfg change to strip debug info" and quotes a 3 KB binary "if
compiled with strip". **[measured]** the template at 4608 bytes is the *stripped* size and it is
what `-Wl,-s` alone produces. Leave both commented while iterating: without symbols you cannot run
the `Dl_` diagnostic in `reference/runtime.md` Section 3.

## 7. Optimization reality

- `--opt:none` at the Nim level plus `-Os` (or `-O0`) at the C level is the repo's combination;
  `src/0x03` uses `--opt:size` and `-Os`, `src/0x05` uses `--opt:size` with `-O0`.
- The deck: "Various optimization levels (`-O0`, `-O1`, ...) yields different results. For these
  results, `-Os`, was used." So `-O` level is not cosmetic - it changes the emitted code and the
  size, and a technique that depends on code shape can regress when you change it.
- "Changing gcc versions allow for different results, gcc version 13.2.0 has access to `-Oz`,
  which results in slightly smaller shellcode." The deck also notes cpp output "might yield
  various code sizes", and to "Play with your compiler".
- **This repo's builds need `--t:"-fno-builtin"` on gcc 13 [measured].** With `-Os`, gcc's loop
  idiom recognition turns the byte loop in `utils/gpa.nim`'s private `strlenA` into a call to
  libc `strlen`, and the link fails with
  `undefined reference to 'strlen'` from `getProcAddressHash`. gcc 11.1.0 (the deck's toolchain)
  did not perform that transform, which is why the repo works without the flag. `-fno-builtin` is
  the semantically right guard for a CRT-less target: gcc must never be allowed to expand your
  loops or your calls into a libc that will not be linked.

## 8. DLL size recipe

A nimless DLL that links `NimMain` comes out around 44 KB, because `NimMain` is referenced by
machinery the linker cannot collect. The README documents the measured pair:
44 257 bytes -> 5 120 bytes after deleting the initialization functions from the generated C.

Steps:

```bash
nim c --genscript dll_main.nim       # writes cache/dll_main/@mdll_main.nim.c + compile_dll_main.bat
```

Then truncate the generated `@m<project>.nim.c` starting at the line

```c
N_LIB_PRIVATE void PreMainInner(void) {
```

which removes `PreMainInner`, `PreMain`, `NimMainInner`, `NimMain` and `NimMainModule`, and run the
generated compile script. `src/0x12 - nimless_DLL/make_dll.bat` automates exactly that with a
PowerShell one-liner keyed on the same `N_LIB_PRIVATE void PreMainInner(void) {` pattern, then
moves the DLL out of the cache. Its core:

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

## 9. How to check a build

```bash
# no imports at all - this is the headline property
x86_64-w64-mingw32-objdump -p out.exe | grep -A2 "DLL Name"     # expect: no output
x86_64-w64-mingw32-objdump -p out.exe | grep -iE 'msvcrt|kernel32|user32'   # expect: no output

# sections and where the code landed
x86_64-w64-mingw32-objdump -h out.exe

# entry stub at the head of .text
x86_64-w64-mingw32-objdump -d out.exe | sed -n '1,20p'

file out.exe            # PE32+ executable (console) x86-64
ls -l out.exe           # kilobytes, not megabytes

# what Nim/gcc actually ran
python3 -c "import json;d=json.load(open('cache/<proj>/<out>.json'));print(d['linkcmd'])"

# the 'you called a WinAPI directly' diagnostic - needs an UNSTRIPPED build
x86_64-w64-mingw32-nm out.exe | grep 'Dl_'
```

Note the json file is named after the **output** binary, not the project: with
`-o:verify_debug.exe` the file is `cache/main/verify_debug.json`, and only a build with the
default output name produces `cache/main/main.json` as the deck describes.

**[measured] reference numbers** for the template (nim 2.2.10 / winim 4.0.0 / gcc `13-win32` /
ld 2.41):

| Build | Size | Sections | Imports | Runs |
|---|---|---|---|---|
| `nim c -d:mingw -o:verify_stripped.exe main.nim` | 4 608 B | 5 (`.text` 0x470, `.data` 0x60, `.rdata` 0x10, `.idata` 0x18, `.reloc` 0xc) | 0 | exit 42 |
| same + `-d:malDebug` | 4 608 B | 5 | 0 | prints, exit 42 |
| same + `--l:"-T./script.ld"` | 4 096 B | 4 (no `.idata`) | 0 | rejected by loader |
| base-0 recipe (`--image-base 0x0`, `. = 0x0`) | 4 096 B | 4, `.text` at RVA 0 | 0 | not run (extraction artifact) |
| `-d:malDebug` + one direct winim call, unstripped | 15 231 B | - | 0 | page fault at RIP 0 |

`.idata` at 0x18 bytes is the empty import-descriptor terminator; there is no `DLL Name` entry
behind it. The 4 608 -> 4 096 difference in the scripted build is that terminator section plus
realignment.

## 10. Cross-compiling from Linux

The repo ships a devcontainer and the root `README.md` gives the entire rule:

> "A linux devcontainer is provided to aid in creating a reproducible environment. You will just
> need to add `-d:mingw` to either your build command or `nim.cfg` file."

The template deliberately keeps `-d:mingw` **out** of `nim.cfg`: the config describes the artifact
contract, the define describes where you are building from. Add it on the command line when
cross-compiling, or add it to the config if your project only ever builds from Linux.

**Flag order matters** **[measured]** on nim 2.2.10: options must come *before* the project file.

```bash
nim c -d:mingw -d:malDebug -o:verify_debug.exe main.nim   # correct
nim c -d:mingw main.nim -o:verify_debug.exe               # Error: arguments can only be given
                                                          # if the '--run' option is selected
```

After the project file, nim treats tokens as arguments for the compiled program.

### Toolchain version sensitivity

The deck publishes its own versions and warns: "This should work with other Nim and gcc versions,
might need slight modification to code/nim.cfg." Two deltas already observed in this pack on
nim 2.2.10 + gcc 13:

1. `--t:"-fno-builtin"` is required (Section 7).
2. The `script.ld` builds are not loader-valid under ld 2.41 (Section 4).

Neither of these touches the load-bearing part of the contract - `--noMain:on`, `--mm:none`,
`--threads:off`, `-nostdlib`/`-nostartfiles` on both sides, `-ffunction-sections`/
`-fdata-sections`/`--gc-sections`, and `-e<entry>`. Those are what the config is for, and the
template proves them end to end.
