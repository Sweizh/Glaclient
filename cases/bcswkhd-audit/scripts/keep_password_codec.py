#!/usr/bin/env python3
# Recovered codec for [KeepPassword] entries in config.ini of Glacier AuthGate client.
# Reverse-engineered from mfc101f.dll / pkjiobcbzxzvbbccdrlr.exe:
#   encode: func_0x405020(seed=0x522), decode: func_0x405190(seed=0x522)
# Algorithm:
#   pass1 (stream): t = c ^ (state >> 8)          (16-bit)
#                   state = (0x58bf - ((t_low8 + state) * 0x3193)) & 0xffff
#   pass2 (base26): emit chr('A' + t//26), chr('A' + t%26)

SEED   = 0x522
MUL    = 0x3193
SUB    = 0x58bf

def encode(plain: str) -> str:
    state = SEED
    out = []
    for ch in plain:
        v = ord(ch) ^ (state >> 8)          # 16-bit transform
        out.append(v)
        state = (SUB - ((v & 0xFF) + state) * MUL) & 0xFFFF
    cipher = ""
    for v in out:
        cipher += chr(ord("A") + v // 26)
        cipher += chr(ord("A") + v % 26)
    return cipher

def decode(cipher: str) -> str:
    assert len(cipher) % 2 == 0
    state = SEED
    plain = []
    for i in range(0, len(cipher), 2):
        v = (ord(cipher[i]) - ord("A")) * 26 + (ord(cipher[i+1]) - ord("A"))
        plain.append(chr(v ^ (state >> 8)))
        state = (SUB - ((v & 0xFF) + state) * MUL) & 0xFFFF
    return "".join(plain)

if __name__ == "__main__":
    entries = {
        "2202160228": "CAIUGEGICXEK",
        "2205120148": "CBFQBHHNIKAB",
    }
    print("=== [KeepPassword] decoded ===")
    for user, cipher in entries.items():
        plain = decode(cipher)
        print(f"  username={user}  cipher={cipher}  -> password={plain!r}")
        # roundtrip verify
        rt = encode(plain)
        assert rt == cipher, f"roundtrip mismatch: {rt} != {cipher}"
    print("\n[+] roundtrip encode() == cipher verified for both entries")
