#!/usr/bin/env python3
# Triage Uninstall.exe: PE meta, hashes, imports, strings, sections
import struct, hashlib, math, re, datetime

import os
PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/artifacts/extracted/冰川上网客户端/Uninstall.exe"
data = open(PATH, "rb").read()
print(f"size={len(data)} sha256={hashlib.sha256(data).hexdigest()}")
print(f"md5={hashlib.md5(data).hexdigest()}")

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
ts = datetime.datetime.fromtimestamp(timedate, datetime.timezone.utc)
print(f"machine=0x{machine:x} nsec={nsec} timedate={ts} (0x{timedate:x})")
print(f"linker={linker_maj}.{linker_min} magic=0x{magic:x} entry=0x{entry:x} base=0x{image_base:x} subsys={subsystem}")

# checksum
hdr_checksum = struct.unpack_from("<I", data, opt + 64)[0]
print(f"header checksum=0x{hdr_checksum:x}")

sec_off = opt + optsz
raw_end = 0
for i in range(nsec):
    name, vsize, vaddr, rsize, raddr = struct.unpack_from("<8sIIII", data, sec_off + i*40)
    schars = struct.unpack_from("<I", data, sec_off + i*40 + 36)[0]
    raw_end = max(raw_end, raddr + rsize)
    chunk = data[raddr:raddr+rsize]
    ent = 0
    if chunk:
        freq = [0]*256
        for b in chunk: freq[b] += 1
        n = len(chunk)
        ent = -sum((c/n)*math.log2(c/n) for c in freq if c)
    print(f"  {name.decode().strip(chr(0)):10s} va=0x{vaddr:08x} vsz=0x{vsize:08x} raw=0x{raddr:08x}+0x{rsize:08x} ent={ent:.2f} chars=0x{schars:08x}")
if len(data) - raw_end:
    print(f"  OVERLAY: {len(data)-raw_end} bytes at 0x{raw_end:x}: {data[raw_end:raw_end+32].hex()}")

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

imp_rva, imp_sz = struct.unpack_from("<II", data, opt + 96 + 8)
if rva2off(imp_rva):
    off = rva2off(imp_rva)
    while True:
        oft, t2, fc, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if oft == 0 and name_rva == 0: break
        dll = cstr(rva2off(name_rva))
        thunk = oft if oft else ft
        funcs = []
        i = 0
        while True:
            val = struct.unpack_from("<I", data, rva2off(thunk + i*4))[0]
            if val == 0: break
            funcs.append(f"#{val&0xffff}" if val & 0x80000000 else cstr(rva2off(val)+2))
            i += 1
        print(f"  DLL {dll}: {len(funcs)}: {', '.join(funcs[:12])}{'...' if len(funcs)>12 else ''}")
        off += 20

print("\n=== version resource (VS_VERSIONINFO) ===")
for m in re.finditer(rb"V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00", data):
    start = m.start()
    for tag in [b"F\x00i\x00l\x00e\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00",
                b"P\x00r\x00o\x00d\x00u\x00c\x00t\x00N\x00a\x00m\x00e\x00",
                b"C\x00o\x00m\x00p\x00a\x00n\x00y\x00N\x00a\x00m\x00e\x00",
                b"F\x00i\x00l\x00e\x00D\x00e\x00s\x00c\x00r\x00i\x00p\x00t\x00i\x00o\x00n\x00",
                b"O\x00r\x00i\x00g\x00i\x00n\x00a\x00l\x00F\x00i\x00l\x00e\x00n\x00a\x00m\x00e\x00",
                b"L\x00e\x00g\x00a\x00l\x00C\x00o\x00p\x00y\x00r\x00i\x00g\x00h\x00t\x00"]:
        idx = data.find(tag, start, start+0x800)
        if idx != -1:
            vstart = idx + len(tag)
            vbytes = data[vstart:vstart+128]
            txt = vbytes.decode("utf-16-le", "replace").split("\x00")[0]
            print(f"  {tag.decode('utf-16-le')}: {txt}")
    break

print("\n=== notable ANSI strings ===")
pats = re.compile(rb"[\x20-\x7e]{6,}")
hits = 0
for m in pats.finditer(data):
    s = m.group().decode()
    if re.search(r"(?i)uninst|delete|remove|\.exe|\.dll|\.ini|reg|hkey|software|bingchuan|glacier|http|www\.|temp|reboot|shell|run|glac|setup|stratum|astrum|mfc", s):
        print(f"  0x{m.start():06x}  {s[:110]}")
        hits += 1
        if hits > 45: break
