#!/usr/bin/env python3
# PE structure + packer detection for gcsetup.exe
import struct, hashlib

PATH = "/workspace/bcswkhd/gcsetup.exe"
data = open(PATH, "rb").read()

e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
assert data[e_lfanew:e_lfanew+4] == b"PE\0\0"
coff = e_lfanew + 4
machine, nsec, timedate, symptr, nsym, optsz, chars = struct.unpack_from("<HHIIIHH", data, coff)
opt = coff + 20
magic = struct.unpack_from("<H", data, opt)[0]
image_base = struct.unpack_from("<I", data, opt + 28)[0]
entry = struct.unpack_from("<I", data, opt + 16)[0]
linker_maj, linker_min = struct.unpack_from("<BB", data, opt + 2)
subsystem = struct.unpack_from("<H", data, opt + 68)[0]

import datetime
ts = datetime.datetime.fromtimestamp(timedate, datetime.timezone.utc)
print(f"machine=0x{machine:x} nsec={nsec} timedate={ts} (0x{timedate:x})")
print(f"linker={linker_maj}.{linker_min} entry=0x{entry:x} base=0x{image_base:x} subsystem={subsystem}")

sec_off = opt + optsz
size_img = struct.unpack_from("<I", data, opt + 56)[0]
raw_end = 0
for i in range(nsec):
    name, vsize, vaddr, rsize, raddr = struct.unpack_from("<8sIIII", data, sec_off + i*40)
    schars = struct.unpack_from("<I", data, sec_off + i*40 + 36)[0]
    raw_end = max(raw_end, raddr + rsize)
    entropy = 0
    import math
    chunk = data[raddr:raddr+rsize]
    if chunk:
        freq = [0]*256
        for b in chunk: freq[b] += 1
        n = len(chunk)
        entropy = -sum((c/n)*math.log2(c/n) for c in freq if c)
    print(f"  {name.decode().strip(chr(0)):10s} va=0x{vaddr:08x} vsz=0x{vsize:08x} raw=0x{raddr:08x}+0x{rsize:08x} entropy={entropy:.2f} chars=0x{schars:08x}")

overlay = len(data) - raw_end
print(f"overlay: {overlay} bytes (0x{overlay:x}) at 0x{raw_end:x}")
ov = data[raw_end:raw_end+64]
print(f"overlay head: {ov[:32].hex()}")
print(f"overlay ascii: {ov[:32].decode('ascii','replace')}")

# packer signatures across the whole file
sigs = {
    b"NullsoftInst": "NSIS",
    b"Nullsoft": "NSIS(sig)",
    b"Inno Setup Setup Data": "Inno Setup (new)",
    b"z1\x1eInno Setup": "Inno Setup (0.x)",
    b"InstallShield": "InstallShield",
    b"WISE": "Wise",
    b"7z\xbc\xaf\x27\x1c": "7z SFX",
    b"Rar!\x1a\x07": "RAR SFX",
    b"MZ": "embedded PE?",
    b"PK\x03\x04": "ZIP/Office doc",
    b"UPX!": "UPX",
    b"PEC1": "PECompact",
    b"PEC2": "PECompact2",
    b".UPX0": "UPX section",
    b"nstall": "generic",
}
for sig, name in sigs.items():
    idx = data.find(sig)
    while idx != -1 and idx < len(data):
        # limit reporting for very common signatures
        if sig in (b"MZ", b"Nullsoft"):
            pass
        print(f"  sig {name:24s} @ 0x{idx:x}")
        idx = data.find(sig, idx+1)
        if sig == b"MZ" and idx > 0x400000: break
        if sig != b"MZ":
            break

# imports quick dump
imp_rva, imp_sz = struct.unpack_from("<II", data, opt + 96 + 8)
print(f"import dir rva=0x{imp_rva:x} size=0x{imp_sz:x}")

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

if rva2off(imp_rva):
    off = rva2off(imp_rva)
    while True:
        oft, ts2, fc, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if oft == 0 and name_rva == 0:
            break
        dll = cstr(rva2off(name_rva))
        thunk = oft if oft else ft
        funcs = []
        i = 0
        while True:
            val = struct.unpack_from("<I", data, rva2off(thunk + i*4))[0]
            if val == 0:
                break
            if val & 0x80000000:
                funcs.append(f"#{val & 0xFFFF}")
            else:
                funcs.append(cstr(rva2off(val) + 2))
            i += 1
        print(f"  DLL {dll}: {len(funcs)} funcs; sample: {', '.join(funcs[:8])}")
        off += 20

# resource dir: look for version info / RCDATA (NSIS data usually in .text or overlay)
print("\n--- search for installer markers in raw ---")
for pat in [b"nsis", b"NSIS", b"inno", b"Inno", b"setup.exe", b"Setup.exe", b"uninst", b"Uninstall"]:
    idx = data.find(pat)
    cnt = 0
    while idx != -1 and cnt < 3:
        print(f"  {pat} @0x{idx:x}")
        idx = data.find(pat, idx+1)
        cnt += 1
