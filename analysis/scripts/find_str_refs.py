#!/usr/bin/env python3
# Find "encrypt_type" and related strings in mfc101f.dll (ANSI + wide), print VAs,
# then find code references (push/mov imm32) in .text.
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

vaddr_t, raddr_t, rsize_t = None, None, None
for name, vaddr, raddr, rsize in secs:
    if name == ".text":
        vaddr_t, raddr_t, rsize_t = vaddr, raddr, rsize
blob = data[raddr_t:raddr_t + rsize_t]

for label, needle in [
    ("encrypt_type", "encrypt_type"),
    ("mymethod", "mymethod"),
    ("login_client", "login_client"),
    ("&data=", "&data="),
    ("&time=", "&time="),
    ("&debug=", "&debug="),
    ("HHMMSS", "%02d:%02d:%02d"),
    ("language", "&language="),
]:
    for enc, w in (("ansi", needle.encode("latin-1")), ("wide", needle.encode("utf-16-le"))):
        i = data.find(w)
        while i >= 0:
            va = off2va(i)
            if va:
                # find refs in .text
                pat = struct.pack("<I", va)
                refs = []
                j = 0
                while True:
                    j = blob.find(pat, j)
                    if j < 0:
                        break
                    prev = blob[j-1] if j > 0 else 0
                    kind = {0x68: "push", 0xb8: "mov eax", 0xb9: "mov ecx", 0xba: "mov edx",
                            0xbb: "mov ebx", 0xbe: "mov esi", 0xbf: "mov edi"}.get(prev, f"prev {prev:02x}")
                    refs.append(f"0x{off2va(raddr_t + j):08x}({kind})")
                    j += 1
                print(f"[{enc}] {label!r} @ 0x{va:08x}  refs: {', '.join(refs) if refs else 'none'}")
            i = data.find(w, i + 1)
            # limit duplicates
            if enc == "ansi" and i > 0x40f000 + 0x100000000 - image_base:
                break
print("done")
