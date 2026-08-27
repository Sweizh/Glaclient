#!/usr/bin/env python3
# Identify installer engine via strings in stub + overlay magic analysis
import re, struct

PATH = "/workspace/bcswkhd/gcsetup.exe"
data = open(PATH, "rb").read()
OVERLAY = 0x2d600

# 1. all meaningful ANSI strings in the stub (before overlay)
stub = data[:OVERLAY]
strs = set()
for m in re.finditer(rb"[\x20-\x7e]{5,}", stub):
    s = m.group().decode()
    strs.add((m.start(), s))

interesting = [(o, s) for o, s in strs if re.search(
    r"(?i)installshield|shield|isetup|_isres|_isengine|setup\.|\.ins|\.cab|\.hdr|data1|iscript|iwire|"
    r"factory|indigo|wise|inno|nsis|nullsoft|boot|uninst|kernel\.dat|lang|english\.?dll|glacier|bingchuan|"
    r"version|copyright|company|product|comment|fileversion|internalname|originalfilename|"
    r"\.exe|\.dll|\.ins$|\.dat|language|wizard", s)]
for o, s in sorted(set(interesting)):
    print(f"0x{o:06x}  {s[:110]}")

print("\n=== overlay structure probes ===")
ov = data[OVERLAY:]
# InstallShield 5/6/7 package headers
probes = {
    b"ISc(": "IS5 cab signature?",
    b"\x0d\x00\x61\x8c": "IS6/7 cab magic 0x8C61000D",
    b"\x28\x63\x29\x49": "IScab (IS5)",
    b"ISu(": "ISu?",
    b"ISetupFile": "InstallShield SetupFile",
    b"MSZIP": "MSZIP",
    b"MSCF": "CAB (MSCF)",
    b"IS\x03\x00\x00\x00": "IS3",
    b"r\x02\x00\x00MSFT": "MSFT",
}
for sig, name in probes.items():
    idx = ov.find(sig)
    if idx != -1:
        print(f"  {name} found at overlay+0x{idx:x} (abs 0x{OVERLAY+idx:x})")

# dump first 0x40 bytes as dwords
print("\noverlay dwords[0..16]:", [hex(x) for x in struct.unpack_from("<16I", ov, 0)])

# 2. strings inside overlay - look for script engine / file names
print("\n=== overlay strings (first 60) ===")
seen = 0
for m in re.finditer(rb"[\x20-\x7e]{6,}", ov[:0x200000]):
    s = m.group().decode()
    if seen > 60: break
    print(f"  ov+0x{m.start():06x}  {s[:100]}")
    seen += 1
