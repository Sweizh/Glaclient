#!/usr/bin/env python3
# Locate file offsets of key strings in mfc101f.dll, compute VAs,
# and dump section headers so we can find xrefs in disassembly.
import struct, sys

PATH = "/workspace/cases/bcswkhd-audit/artifacts/extracted/冰川上网客户端/mfc101f.dll"
data = open(PATH, "rb").read()

# --- PE header parsing ---
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
assert data[e_lfanew:e_lfanew+4] == b"PE\0\0"
coff = e_lfanew + 4
machine, nsec, _, _, _, optsz, _ = struct.unpack_from("<HHIIIHH", data, coff)
opt = coff + 20
magic = struct.unpack_from("<H", data, opt)[0]
image_base = struct.unpack_from("<I", data, opt + 28)[0]
print(f"machine=0x{machine:x} nsec={nsec} optmagic=0x{magic:x} image_base=0x{image_base:x}")

secs = []
sec_off = opt + optsz
for i in range(nsec):
    name, vsize, vaddr, rsize, raddr = struct.unpack_from("<8sIIII", data, sec_off + i*40)
    name = name.rstrip(b"\0").decode()
    secs.append((name, vaddr, vsize, raddr, rsize))
    print(f"  {name:<8} VA=0x{vaddr:08x} VSize=0x{vsize:x} RAW=0x{raddr:08x} RSz=0x{rsize:x}")

def off_to_va(off):
    for name, vaddr, vsize, raddr, rsize in secs:
        if raddr <= off < raddr + rsize:
            return image_base + vaddr + (off - raddr)
    return None

targets = {
    "KeepPassword_u": "KeepPassword".encode("utf-16-le"),
    "KeepPassword_a": b"KeepPassword",
    "username_u": "username".encode("utf-16-le"),
    "keeppassword_u": "keeppassword".encode("utf-16-le"),
    "blob_pcqwaou": b"pcqwaou",
    "login_client": b"&login_client=win32",
    "auth_ok": b"auth_ok",
    "keepalive_a": b"keepalive",
    "encrypt_type": b"pInfo->encrypt_type:%d",
    "AuthGate_u": "AuthGate".encode("utf-16-le"),
    "UsedMac_u": "UsedMac".encode("utf-16-le"),
}

print("\n=== string offsets -> VAs ===")
for label, pat in targets.items():
    idx = 0
    hits = []
    while True:
        i = data.find(pat, idx)
        if i < 0: break
        hits.append(i)
        idx = i + 1
        if len(hits) > 6: break
    for h in hits[:6]:
        va = off_to_va(h)
        print(f"  {label:<18} file_off=0x{h:08x} VA=0x{va:08x}" if va else f"  {label:<18} file_off=0x{h:08x} VA=?")
