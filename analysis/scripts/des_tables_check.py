#!/usr/bin/env python3
# Verify DES tables in mfc101f.dll against standard DES constants.
# Table VAs (image base 0x400000):
#   IP  = 0x4107b0 (64)   E   = 0x4107f0 (48)   S   = 0x410820 (512)
#   P   = 0x410a20 (32)   FP  = 0x410a40 (64)
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
    secs.append((vaddr, raddr, rsize))

def va2off(va):
    rva = va - image_base
    for vaddr, raddr, rsize in secs:
        if vaddr <= rva < vaddr + rsize:
            return raddr + (rva - vaddr)
    return None

def read(va, n):
    off = va2off(va)
    assert off is not None, f"VA 0x{va:x} not mapped"
    chunk = data[off:off+n]
    assert len(chunk) == n, f"short read at VA 0x{va:x}: {len(chunk)}/{n}"
    return list(chunk)

# ---- standard DES tables (1-based in FIPS; convert to 0-based) ----
# NOTE: binary tables are 1-BASED (FIPS style); the code indexes input bits as
# bits[table[i] - 1] (see the -0x1(%ebx,%ecx) addressing), so compare directly.
STD_IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
          62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
          57,49,41,33,25,17, 9,1,59,51,43,35,27,19,11,3,
          61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]

STD_E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
         16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]

STD_P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
         2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]

STD_FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
          38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
          36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
          34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]

STD_S = [
 [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
  0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
  15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
 [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
  3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
  13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
 [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
  13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
  13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
  1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
 [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
  13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
  10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
  3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
 [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
  14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
  11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
 [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
  10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
  4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
 [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
  13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
  6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
 [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
  1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
  2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]

bin_ip = read(0x4107b0, 64)
bin_e  = read(0x4107f0, 48)
bin_s  = read(0x410820, 512)
bin_p  = read(0x410a20, 32)
bin_fp = read(0x410a40, 64)

def cmp(name, got, want):
    ok = got == want
    print(f"{name:12s} VA 0x{ {'IP':0x4107b0,'E':0x4107f0,'S':0x410820,'P':0x410a20,'FP':0x410a40}[name]:x}  match={ok}")
    if not ok:
        diffs = [(i, g, w) for i, (g, w) in enumerate(zip(got, want)) if g != w]
        print(f"  {len(diffs)} differing entries, first 10: {diffs[:10]}")
    return ok

results = []
results.append(cmp("IP", bin_ip, STD_IP))
results.append(cmp("E",  bin_e,  STD_E))
results.append(cmp("P",  bin_p,  STD_P))
results.append(cmp("FP", bin_fp, STD_FP))

s_ok = True
for i in range(8):
    got = bin_s[i*64:(i+1)*64]
    if got != STD_S[i]:
        s_ok = False
        diffs = [(j, g, w) for j, (g, w) in enumerate(zip(got, STD_S[i])) if g != w]
        print(f"S-box {i+1}: {len(diffs)} diffs, first 10: {diffs[:10]}")
print(f"{'S-boxes':12s} VA 0x410820  match={s_ok} (layout: 8 x 64, addr = base + 64*i + 16*row + col)")
results.append(s_ok)

print()
if all(results):
    print("==> ALL TABLES MATCH STANDARD DES. Algorithm = textbook DES (bitslice byte-per-bit impl).")
else:
    print("==> CUSTOM/SCRAMBLED TABLES DETECTED - not standard DES, see diffs above.")
