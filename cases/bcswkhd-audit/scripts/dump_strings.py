#!/usr/bin/env python3
# Dump wide/ANSI strings at given VAs in mfc101f.dll .rdata
import struct, sys

PATH = "/workspace/cases/bcswkhd-audit/artifacts/extracted/冰川上网客户端/mfc101f.dll"
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

def dump_wide(va, maxn=64):
    off = va2off(va)
    out = []
    for i in range(maxn):
        w = struct.unpack_from("<H", data, off + i*2)[0]
        if w == 0:
            break
        out.append(chr(w))
    return "".join(out)

def dump_ansi(va, maxn=64):
    off = va2off(va)
    out = []
    for i in range(maxn):
        b = data[off + i]
        if b == 0:
            break
        out.append(chr(b))
    return "".join(out)

# key format / context strings seen in the &data= builder
for va in (0x40f618, 0x40f63c, 0x40f654, 0x40f680, 0x40f684, 0x40f68c):
    w = dump_wide(va)
    a = dump_ansi(va)
    print(f"VA 0x{va:06x}: wide={w!r}  ansi={a!r}")

# also dump hex around 0x4107a0 (shift table) and 0x410738 (PC1) for verification
def hexdump(va, n):
    off = va2off(va)
    b = data[off:off+n]
    return " ".join(f"{x:02x}" for x in b)

print("\nPC1 table @0x410738 (56):", hexdump(0x410738, 56))
print("PC2 table @0x410770 (48):", hexdump(0x410770, 48))
print("shifts  @0x4107a0 (16):", hexdump(0x4107a0, 16))
