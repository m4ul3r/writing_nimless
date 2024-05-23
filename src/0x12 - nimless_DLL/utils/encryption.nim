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