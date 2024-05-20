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