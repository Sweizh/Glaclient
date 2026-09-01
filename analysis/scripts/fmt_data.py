#!/usr/bin/env python3
# Extract wide format string at .rdata 0x40f654 and neighbors (plaintext layout for &data=)
import struct

import os
PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/artifacts/extracted/冰川上网客户端/mfc101f.dll"
data = open(PATH, "rb").read()
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
coff = e_lfanew + 4
optsz = struct.unpack_from("<H", data, coff + 16)[0]
opt = coff + 20
nsec = struct.unpack_from("<H", data, coff + 2)[0]
sec_off = opt + optsz
secs = []
for i in range(nsec):
    name, vsize, vaddr, rsize, raddr = struct.unpack_from("<8sIIII", data, sec_off + i*40)
    secs.append((vaddr, raddr, rsize))
def va2off(va):
    rva = va - 0x400000
    for vaddr, raddr, rsize in secs:
        if vaddr <= rva < vaddr + rsize:
            return raddr + (rva - vaddr)
    return None

def wide(va, maxlen=120):
    off = va2off(va)
    raw = data[off:off+maxlen*2]
    s = raw.split(b"\x00\x00")[0]
    try:
        return s.decode("utf-16-le")
    except Exception:
        return repr(s)

# the format string used at 0x405b02 (plaintext assembly for DES payload)
print("0x40f654 (data= plaintext fmt):", repr(wide(0x40f654)))
# neighbors for context
for va in (0x40f600, 0x40f62c, 0x40f63c, 0x40f670, 0x40f690, 0x40f6b0):
    print(f"0x{va:x}:", repr(wide(va, 80)))
