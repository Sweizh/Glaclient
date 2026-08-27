#!/usr/bin/env python3
# Scan Astrum InstallWizard overlay: script commands, file table, config
import re

PATH = "/workspace/bcswkhd/gcsetup.exe"
data = open(PATH, "rb").read()
ov = data[0x2d600:]

# 1. find key file names / script keywords across whole overlay
print("=== keyword hits in overlay ===")
kws = [b"Glaclient", b"mfc101f", b"mfc100u", b"msvcr100", b"Packet.dll", b"Uninstall",
       b"bingchuan", b"glacier", b"bcswkhd", b"304|3080", b"client_check",
       b"config.ini", b"www.", b"http", b"Version", b"INSTALLDIR", b"PROGRAMDIR",
       b".exe", b".dll", b".ini", b"setup", b"batch", b"run", b"exec", b"copy", b"register",
       b"REG", b"HKEY", b"CreateFile", b"WriteFile"]
for kw in kws:
    idx = ov.find(kw)
    hits = 0
    while idx != -1 and hits < 4:
        ctx = ov[max(0,idx-40):idx+90]
        printable = re.sub(rb"[^\x20-\x7e]", b".", ctx).decode()
        print(f"  [{kw.decode():12s}] ov+0x{idx:06x}: ...{printable}...")
        idx = ov.find(kw, idx+1)
        hits += 1

# 2. count total printable runs to gauge plaintext regions
runs = [(m.start(), m.end()) for m in re.finditer(rb"[\x20-\x7e]{8,}", ov)]
total = sum(e-s for s, e in runs)
print(f"\nplaintext-run bytes: {total}/{len(ov)} ({100*total/len(ov):.1f}%)  runs={len(runs)}")

# 3. find the big gaps (compressed/encrypted data) between plaintext zones
print("\n=== structure: large non-printable regions ===")
prev_end, gaps = 0, []
for s, e in runs:
    if s - prev_end > 0x2000:
        gaps.append((prev_end, s, s-prev_end))
    prev_end = max(prev_end, e)
if len(ov) - prev_end > 0x2000:
    gaps.append((prev_end, len(ov), len(ov)-prev_end))
for gs, ge, gl in gaps:
    print(f"  gap 0x{gs:06x} - 0x{ge:06x}  len=0x{gl:x} ({gl} bytes)  head={ov[gs:gs+16].hex()}")

# 4. Astrum script files: look for 'installer.cfg' / 'setup.dat' markers & trailer
print("\n=== tail of overlay (last 0x100) ===")
tail = ov[-0x100:]
print(re.sub(rb"[^\x20-\x7e]", b".", tail).decode())
print(tail[-32:].hex())
