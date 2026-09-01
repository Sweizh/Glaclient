#!/usr/bin/env python3
# Parse import tables of mfc101f.dll and map IAT slot VA -> symbol name
import struct

import os
PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/artifacts/extracted/冰川上网客户端/mfc101f.dll"
data = open(PATH, "rb").read()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
coff = e_lfanew + 4
optsz = struct.unpack_from("<H", data, coff + 16)[0]
opt = coff + 20
image_base = struct.unpack_from("<I", data, opt + 28)[0]
imp_rva, imp_sz = struct.unpack_from("<II", data, opt + 96 + 8)  # data dir 1

# section translate
nsec = struct.unpack_from("<H", data, coff + 2)[0]
sec_off = opt + optsz
secs = []
for i in range(nsec):
    name, vsize, vaddr, rsize, raddr = struct.unpack_from("<8sIIII", data, sec_off + i*40)
    secs.append((vaddr, raddr, rsize))

def rva2off(rva):
    for vaddr, raddr, rsize in secs:
        if vaddr <= rva < vaddr + rsize:
            return raddr + (rva - vaddr)
    return None

def cstr(off):
    end = data.index(b"\0", off)
    return data[off:end].decode("ascii", "replace")

iat = {}
off = rva2off(imp_rva)
while True:
    oft, ts, fc, name_rva, ft = struct.unpack_from("<IIIII", data, off)
    if oft == 0 and name_rva == 0:
        break
    dll = cstr(rva2off(name_rva))
    thunk = oft if oft else ft
    i = 0
    while True:
        val = struct.unpack_from("<I", data, rva2off(thunk + i*4))[0]
        if val == 0:
            break
        slot = image_base + ft + i*4
        if val & 0x80000000:
            iat[slot] = f"{dll}!#{val & 0xFFFF}"
        else:
            # hint/name: skip 2-byte hint
            iat[slot] = f"{dll}!{cstr(rva2off(val) + 2)}"
        i += 1
    off += 20

# print sorted IAT of interest (code uses 0x40e0xx..0x40e6xx)
for slot in sorted(iat):
    if 0x40e000 <= slot <= 0x40e700:
        print(f"  0x{slot:08x} -> {iat[slot]}")
