#!/usr/bin/env python3
# Dump .rdata 0x40f460-0x40f500 strings (routing table) 
import struct

PATH = "/workspace/cases/bcswkhd-audit/artifacts/extracted/冰川上网客户端/mfc101f.dll"
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

va = 0x40f460
print("=== ANSI strings 0x40f460-0x40f510 (routing table) ===")
while va < 0x40f510:
    off = va2off(va)
    raw = data[off:off+48]
    n = 0
    while n < len(raw) and 0x20 <= raw[n] < 0x7f:
        n += 1
    if n >= 1 and raw[n:n+1] == b"\x00":
        print(f"  0x{va:x}: {raw[:n].decode()!r}")
        va += (n + 1 + 3) & ~3
        continue
    va += 1
