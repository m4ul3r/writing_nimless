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