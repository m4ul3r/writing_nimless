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
