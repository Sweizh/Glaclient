#!/usr/bin/env python3
# Brute-force simple encodings (XOR / add / sub) on:
# 1. KeepPassword entries from config.ini
# 2. Obfuscated long string found in mfc101f.dll
import string

PW1 = "CAIUGEGICXEK"
PW2 = "CBFQBHHNIKAB"
BLOB = ("pcqwaou^lr^lr^lr_msaoudpvcqwfrxdrxfrxdrxfrxesyhtzhtxkw{kw{lw{kw{lw{jv|jt{htz"
        "gqxgsyiszgswgrvequeptcprfsuertfsuhuwivxhuwhuwivxhttfrrdppeqqgsshttgssesrdqsequequ"
        "frvfrvfrvfsufsucprdqsfsuhuwjwyjwyjwyivxmy}my}my}o{")

PRINTABLE = set(string.ascii_letters + string.digits + " ._-:/@=&?[]()%$#!,;+*")
DIGITS = set(string.digits)

def score(s, charset):
    return sum(1 for c in s if c in charset) / max(1, len(s))

print("=== 1. KeepPassword single-byte transforms ===")
for name, transform in [("xor", lambda b, k: b ^ k), ("add", lambda b, k: (b + k) & 0xFF), ("sub", lambda b, k: (b - k) & 0xFF)]:
    for k in range(256):
        d1 = bytes(transform(b, k) for b in PW1.encode())
        d2 = bytes(transform(b, k) for b in PW2.encode())
        try:
            s1, s2 = d1.decode("ascii"), d2.decode("ascii")
        except UnicodeDecodeError:
            continue
        if score(s1, DIGITS) == 1.0 and score(s2, DIGITS) == 1.0:
            print(f"  [DIGITS] {name} k={k} (0x{k:02x},{chr(k) if 32<=k<127 else '?'}) -> {s1} / {s2}")
        elif score(s1, PRINTABLE) == 1.0 and score(s2, PRINTABLE) == 1.0 and k > 0:
            if score(s1, DIGITS) >= 0.8 and score(s2, DIGITS) >= 0.8:
                print(f"  [MOSTLY-DIGIT] {name} k={k} -> {s1} / {s2}")

print("\n=== 2. KeepPassword per-position transforms (key = ASCII index) ===")
# Try: cipher = plain + f(i) e.g. classic A=0 table with position offset
for offset_mode in range(3):
    outs = []
    for pw in (PW1, PW2):
        o = ""
        for i, c in enumerate(pw):
            v = ord(c) - ord("A")
            if offset_mode == 0:   # plain value 0-25
                o += chr(v + 0x30) if v < 10 else f"[{v}]"
            elif offset_mode == 1:  # value - i
                t = v - i
                o += chr(t + 0x30) if 0 <= t < 10 else f"[{t}]"
            else:                   # value + i
                t = v + i
                o += chr(t + 0x30) if 0 <= t < 10 else f"[{t}]"
        outs.append(o)
    print(f"  mode={offset_mode}: {outs[0]} | {outs[1]}")

print("\n=== 3. Blob single-byte XOR brute force (readable candidates) ===")
for k in range(1, 256):
    d = bytes(b ^ k for b in BLOB.encode())
    try:
        s = d.decode("ascii")
    except UnicodeDecodeError:
        continue
    if score(s, PRINTABLE) >= 0.95 and score(s, set(string.ascii_lowercase + string.digits + "._-:/=&?")) >= 0.9:
        print(f"  k=0x{k:02x}: {s[:120]}")

print("\n=== 4. Blob XOR with short repeating keys (2-4 bytes, printable subset keys) ===")
import itertools
key_chars = [0x00, 0x01, 0x02, 0x03, 0x05, 0x0f, 0x1f, 0x20, 0x2b, 0x2d, 0x5b, 0x7f, 0xff]
found = 0
for klen in (2, 3, 4):
    for key in itertools.product(key_chars, repeat=klen):
        d = bytes(b ^ key[i % klen] for i, b in enumerate(BLOB.encode()))
        try:
            s = d.decode("ascii")
        except UnicodeDecodeError:
            continue
        if score(s, PRINTABLE) >= 0.98:
            hits = sum(1 for w in ("login", "pass", "user", "http", "cgi", "keep", "auth", ".ini", "url") if w in s.lower())
            if hits:
                print(f"  key={bytes(key).hex()}: {s[:140]}")
                found += 1
                if found > 8: break
    if found > 8: break

print("\n=== 5. Blob additive shift brute force ===")
for k in range(1, 256):
    d = bytes((b + k) & 0xFF for b in BLOB.encode())
    try:
        s = d.decode("ascii")
    except UnicodeDecodeError:
        continue
    if score(s, PRINTABLE) >= 0.95 and score(s, set(string.ascii_lowercase + string.digits + "._-:/=&?")) >= 0.9:
        print(f"  +k=0x{k:02x}: {s[:120]}")
