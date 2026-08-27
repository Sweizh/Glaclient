#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
冰川上网客户端 `&data=` 载荷编解码器（从 mfc101f.dll 完整逆向恢复）
Recovered from mfc101f.dll (Glaclient v4.12, disguised as MFC101F.DLL).

算法 / Algorithm:
    key     = time_str "HH:MM:SS" (8 ASCII bytes; identical to the &time= parameter)
    cipher  = DES-ECB(plaintext, key) with zero padding to 8-byte blocks
    data    = uppercase hex(cipher)

Function map (mfc101f.dll, image base 0x400000):
    0x40a760  key schedule entry: 64 key bits -> PC1 (table @0x410738)
    0x40a820  16 rounds: left-rotate C/D by shifts[@0x4107a0] + PC2 (table @0x410770)
              -> 16 subkeys of 48 bits each at ctx+1+48*i
    0x40aa00  DES encrypt block: IP(@0x4107b0) -> 16 Feistel rounds -> swap -> FP(@0x410a40)
    0x40ab80  DES decrypt block
    0x40ad10  round: E(@0x4107f0) xor K[i] -> S-boxes(@0x410820) -> P(@0x410a20) -> xor L
    0x40b300  ECB encrypt wrapper (zero padding, output at ctx+0x6eb)
    0x40b440  ECB decrypt wrapper (output at ctx+0x26eb)
    0x40b280  bits -> uppercase hex string
All 8 tables byte-verified identical to standard (FIPS 46) DES - see des_tables_check.py.
"""
import struct

# ---- standard DES tables (as in the binary, 1-based where indices) ----
IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
      57,49,41,33,25,17, 9,1,59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
      38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
      36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
      34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
E  = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
      16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
P  = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
      2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
PC1 = [57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,10, 2,
       59,51,43,35,27,19,11, 3,60,52,44,36,63,55,47,39,
       31,23,15, 7,62,54,46,38,30,22,14, 6,61,53,45,37,
       29,21,13, 5,28,20,12, 4]
PC2 = [14,17,11,24, 1, 5, 3,28,15, 6,21,10,23,19,12, 4,
       26, 8,16, 7,27,20,13, 2,41,52,31,37,47,55,30,40,
       51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
S = [
 [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
 [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
 [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
  13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
 [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
  10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
 [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
 [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
 [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
 [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
]

def _bits(block8):
    return [(b >> (7 - i)) & 1 for b in block8 for i in range(8)]

def _pack(bits):
    out = bytearray(8)
    for i, b in enumerate(bits):
        out[i >> 3] |= (b & 1) << (7 - (i & 7))
    return bytes(out)

def _xor(a, b):
    return [x ^ y for x, y in zip(a, b)]

def _perm(table, bits, n_out):
    return [bits[t - 1] for t in table[:n_out]]

def subkeys(key8):
    k = _bits(key8)
    cd = _perm(PC1, k, 56)
    c, d = cd[:28], cd[28:]
    out = []
    for s in SHIFTS:
        c = c[s:] + c[:s]
        d = d[s:] + d[:s]
        out.append(_perm(PC2, c + d, 48))
    return out

def _f(r, sk):
    e = _perm(E, r, 48)
    x = _xor(e, sk)
    out = []
    for i in range(8):
        six = x[i*6:(i+1)*6]
        row = (six[0] << 1) | six[5]
        col = (six[1] << 3) | (six[2] << 2) | (six[3] << 1) | six[4]
        v = S[i][row*16 + col]
        out += [(v >> 3) & 1, (v >> 2) & 1, (v >> 1) & 1, v & 1]
    return _perm(P, out, 32)

def _des_block(block8, sks):
    b = _bits(block8)
    b = _perm(IP, b, 64)
    l, r = b[:32], b[32:]
    for sk in sks:
        l, r = r, _xor(l, _f(r, sk))
    return _pack(_perm(FP, r + l, 64))

def des_ecb_encrypt(plain, key8):
    sks = subkeys(key8)
    pad = (-len(plain)) % 8
    data = plain + b"\x00" * pad          # binary zeroes zero-padding, per 0x40b300
    return b"".join(_des_block(data[i:i+8], sks) for i in range(0, len(data), 8))

def des_ecb_decrypt(cipher, key8):
    sks = subkeys(key8)[::-1]
    out = b"".join(_des_block(cipher[i:i+8], sks) for i in range(0, len(cipher), 8))
    return out.rstrip(b"\x00")            # payload is ASCII, zero-trim safe

# ---------- protocol-level API ----------
def make_key(time_str):
    """time_str = the &time= value, e.g. '09:30:15' (local time HH:MM:SS)."""
    kb = time_str.encode("ascii")
    if len(kb) != 8:
        raise ValueError("key must be 'HH:MM:SS' (8 chars)")
    return kb

def decrypt_data(data_hex, time_str):
    """Wireshark capture -> plaintext: pass data= value and the time= value."""
    return des_ecb_decrypt(bytes.fromhex(data_hex), make_key(time_str))

def encrypt_data(plaintext, time_str):
    """plaintext (str/bytes) -> data= value (uppercase hex)."""
    pb = plaintext.encode("ascii") if isinstance(plaintext, str) else plaintext
    return des_ecb_encrypt(pb, make_key(time_str)).hex().upper()

# ---------- self-tests ----------
if __name__ == "__main__":
    # 1) NBS known-answer test: key/pt = all zero -> 8CA64DE9C1B123A7
    kat = _des_block(b"\x00" * 8, subkeys(b"\x00" * 8))
    assert kat.hex().upper() == "8CA64DE9C1B123A7", kat.hex()
    print("[+] NBS KAT passed: DES(0,0) = 8CA64DE9C1B123A7  (implementation = textbook DES)")

    # 2) roundtrip with a realistic time key
    t, pt = "14:23:07", "2205120148|025519|STAFF-PC"
    ct_hex = encrypt_data(pt, t)
    rt = decrypt_data(ct_hex, t)
    assert rt.decode("ascii") == pt
    print(f"[+] roundtrip OK: key={t!r} data={ct_hex}")
    print(f"    plaintext recovered: {rt.decode('ascii')!r}")

    # 3) demo: sniffed request -> credentials
    sniff = "un=2205120148&mymethod=login&time=08:05:33&data=47F1A2C33B09E7D5A1C4F6B2D8E09377"
    print(f"[+] demo decrypt: {decrypt_data('47F1A2C33B09E7D5A1C4F6B2D8E09377', '08:05:33')!r}")
