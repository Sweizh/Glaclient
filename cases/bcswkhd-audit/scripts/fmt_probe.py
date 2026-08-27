#!/usr/bin/env python3
# Probe both ANSI and wide strings in .rdata 0x40f400-0x40f690
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

print("=== raw hex 0x40f4e0-0x40f560 ===")
off = va2off(0x40f4e0)
print(data[off:off+0x80].hex())

print("\n=== ANSI strings 0x40f400-0x40f690 ===")
va = 0x40f400
while va < 0x40f690:
    off = va2off(va)
    if off is None:
        va += 1
        continue
    raw = data[off:off+80]
    if raw[:1] in (b"",) : va += 1; continue
    n = 0
    while n < len(raw) and 0x20 <= raw[n] < 0x7f:
        n += 1
    if n >= 3 and raw[n:n+1] == b"\x00":
        print(f"  0x{va:x}: {raw[:n].decode()!r}")
        va += n + 1
        continue
    va += 1

print("\n=== wide strings 0x40f400-0x40f690 (2-aligned) ===")
va = 0x40f400
while va < 0x40f690:
    off = va2off(va)
    if off is None:
        va += 2
        continue
    raw = data[off:off+160]
    if len(raw) >= 4 and raw[1:2] == b"\x00" and raw[0:1] != b"\x00":
        parts = raw.split(b"\x00\x00")
        s = parts[0].decode("utf-16-le", "replace")
        if s and all(0x20 <= ord(c) < 0x7f for c in s):
            print(f"  0x{va:x}: {s!r}")
            va += len(s)*2 + 2
            continue
    va += 2
