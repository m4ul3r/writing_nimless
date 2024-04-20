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