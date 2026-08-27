#!/usr/bin/env python3
import struct

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

def off2va(off):
    for _, vaddr, raddr, rsize in secs:
        if raddr <= off < raddr + rsize:
            return image_base + vaddr + (off - raddr)
    return None

tv = None
for name, vaddr, raddr, rsize in secs:
    if name == ".text":
        tv = (vaddr, raddr, rsize)
vaddr, raddr, rsize = tv
blob = data[raddr:raddr + rsize]

for va in [0x40ee8c, 0x40f468, 0x40f510]:
    pat = struct.pack("<I", va)
    refs = []
    j = 0
    while True:
        j = blob.find(pat, j)
        if j < 0:
            break
        refs.append(f"0x{off2va(raddr + j):08x}")
        j += 1
    print(f"0x{va:08x} refs: {', '.join(refs) if refs else 'none'}")

# Also: where is pInfo->data (offset 0x10 of the struct) written? Look for the send-thread
# function start: find 'push %ebp; mov %esp,%ebp' before 0x405a94. Scan for int3 padding boundaries.
# The thread func containing 0x405bac likely starts at a ret+int3 boundary after 0x405900.
