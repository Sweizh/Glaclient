#!/usr/bin/env python3
# Find code references to the pInfo debug format strings + login/keepalive/logoff keywords
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

# wide strings for debug prints
for va in [0x40f594, 0x40f5a4, 0x40f5b8, 0x40f5cc, 0x40f604, 0x40f618, 0x40f674]:
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

# search ansi strings for login/keepalive/logoff/auth keywords in whole file
for kw in ["login", "keepalive", "logoff", "auth_ok", "keepalive_ok", "logoff_ok", "auth error", "other error", "online is", "reauth now"]:
    w = kw.encode("latin-1")
    i = data.find(w)
    while i >= 0:
        va = off2va(i)
        if va and va > 0x40f000:  # in .rdata
            # find refs
            pat = struct.pack("<I", va)
            refs = []
            j = 0
            while True:
                j = blob.find(pat, j)
                if j < 0:
                    break
                refs.append(f"0x{off2va(raddr + j):08x}")
                j += 1
            print(f"kw {kw!r} @0x{va:08x} refs: {', '.join(refs) if refs else 'none'}")
            break
        i = data.find(w, i + 1)
