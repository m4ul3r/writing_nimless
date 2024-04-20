proc xorStackString*[I,J](buf: var array[I, byte], key: array[J, byte]) {.inline.}= 
  for i in 0 ..< (buf.len-1):
    buf[i] = key[i mod (key.len-1)] xor buf[i]


