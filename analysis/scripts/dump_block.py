#!/usr/bin/env python3
# Dump the ANSI string block 0x40f580-0x40f720 (.rdata) of mfc101f.dll
import struct

import os
PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/artifacts/extracted/冰川上网客户端/mfc101f.dll"
data = open(PATH, "rb").read()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
coff = e_lfanew + 4
nsec = struct.unpack_from("<H", data, coff + 2)[0]
optsz = struct.unpack_from("<H", data, coff + 16)[0]
opt = coff + 20
image_base = struct.unpack_from("<I", data, opt + 28)[0]
sec_off = opt + optsz
secs = []
for i in range(nsec):
    name, vsize, vaddr, rsize, raddr = struct.unpack_from("<8sIIII", data, sec_off + i*40)
    secs.append((name.rstrip(b"\0").decode(), vaddr, raddr, rsize))

def va2off(va):
    rva = va - image_base
    for _, vaddr, raddr, rsize in secs:
        if vaddr <= rva < vaddr + rsize:
            return raddr + (rva - vaddr)
    return None

start, end = 0x40f580, 0x40f720
off = va2off(start)
cur = start
while cur < end:
    o = va2off(cur)
    e = data.index(b"\0", o)
    s = data[o:e].decode("latin-1", "replace")
    if s:
        print(f"0x{cur:08x}: {s!r}")
    cur += (e - o) + 1
