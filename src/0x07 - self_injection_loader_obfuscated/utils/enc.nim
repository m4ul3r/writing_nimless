proc xorStackString*[I,J](buf: var array[I, byte], key: array[J, byte]) {.inline.} = 
  for i in 0 ..< (buf.len-1):
    asm """
      .byte 0xe9, 0x04, 0x00, 0x00, 0x00
      .byte 0xff, 0xff, 0xff, 0xff
    """
    buf[i] = key[i mod (key.len-1)] xor buf[i]


