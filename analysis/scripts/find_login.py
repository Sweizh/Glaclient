#!/usr/bin/env python3
# Find exact NUL-terminated ANSI 'login' and dump context around mymethod values
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

def off2va(off):
    for _, vaddr, raddr, rsize in secs:
        if raddr <= off < raddr + rsize:
            return image_base + vaddr + (off - raddr)
    return None

# exact 'login\0'
pat = b"login\x00"
i = data.find(pat)
while i >= 0:
    va = off2va(i)
    if va:
        print(f"'login\\0' @ 0x{va:08x}")
    i = data.find(pat, i + 1)

# dump 0x40f460-0x40f520 ansi strings (logoff/keepalive block)
start, end = 0x40f440, 0x40f520
cur = start
while cur < end:
    o = None
    for _, vaddr, raddr, rsize in secs:
        rva = cur - image_base
        if vaddr <= rva < vaddr + rsize:
            o = raddr + (rva - vaddr)
    if o is None:
        cur += 1
        continue
    e = data.index(b"\0", o)
    s = data[o:e].decode("latin-1", "replace")
    if s:
        print(f"0x{cur:08x}: {s!r}")
    cur += (e - o) + 1
