#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
glaclient_reimpl.py — 冰川上网客户端（Glaclient v4.12）替代认证工具
==============================================================
从 mfc101f.dll 完整逆向恢复的协议 reimplementation（本地沙盒/授权网络研究用途）。

协议（全部反汇编验证）：
    GET /cgi/client_check?un=<用户名>&mymethod=<m>&login_client=win32
        &language=<l>&time=<HH:MM:SS>&data=<DES密文hex>&debug=<g>& HTTP/1.0
    Host: <server_ip>:3080

    data= 明文（竖线分隔 9 段，0x407310 构建，尾串 "11111111"）：
        ip|username|password|hostname|<num>|<str1>|<str2>|MAC|11111111
    密钥 = "HH:MM:SS"（8 ASCII 字节，与 &time= 参数同值）
    算法 = DES-ECB，零填充，大写 hex 输出

    mymethod: login → auth_ok / auth error
              keepalive → keepalive_ok
              logoff → logoff_ok / other error

用法：
    python3 glaclient_reimpl.py --server 10.10.94.1 --un 2202160228 --pwd 169332 login
    python3 glaclient_reimpl.py ... keepalive --interval 20
    python3 glaclient_reimpl.py ... logoff
    python3 glaclient_reimpl.py --selftest        # 离线自检（无需网络）
"""
import argparse
import socket
import sys
import time
import uuid

# ---------------------------------------------------------------------------
# DES-ECB 实现（与 mfc101f.dll 0x40a760-0x40b440 逐表一致，NBS KAT 验证）
# ---------------------------------------------------------------------------
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
    data = plain + b"\x00" * pad
    return b"".join(_des_block(data[i:i+8], sks) for i in range(0, len(data), 8))

def des_ecb_decrypt(cipher, key8):
    sks = subkeys(key8)[::-1]
    out = b"".join(_des_block(cipher[i:i+8], sks) for i in range(0, len(cipher), 8))
    return out.rstrip(b"\x00")

# ---------------------------------------------------------------------------
# 本机环境采集（替代原客户端的 0x407310 / GetAdaptersInfo）
# ---------------------------------------------------------------------------
def local_ip(server_ip):
    """UDP connect trick：无需真实发包即可得到默认路由的本机 IP。"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((server_ip, 3080))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return "0.0.0.0"

def local_mac():
    """跨平台 MAC 获取：Linux 读 /sys/class/net，Windows/macOS 用 uuid.getnode()。"""
    import os, glob
    # Linux: 默认路由网卡的 /sys/class/net/<dev>/address
    try:
        with open("/proc/net/route") as f:
            lines = f.read().splitlines()[1:]
        best = None
        for l in lines:
            p = l.split()
            if int(p[1], 16) == 0:  # destination 0.0.0.0 = 默认路由
                best = p[0]
                break
        if best is None:
            for p in glob.glob("/sys/class/net/*/"):
                n = os.path.basename(p.rstrip("/"))
                if n != "lo":
                    best = n
                    break
        if best:
            try:
                with open(f"/sys/class/net/{best}/address") as f:
                    return f.read().strip().upper().replace(":", "")
            except OSError:
                pass
    except OSError:
        pass
    # Windows / macOS / 兜底：uuid.getnode() 返回活动网卡 MAC
    mac = uuid.getnode()
    if (mac >> 40) & 1:  # multicast bit 置位 = 伪随机 MAC（拿不到真实值）
        return "000000000000"
    return "%012X" % mac

def local_hostname():
    return socket.gethostname().upper()

# ---------------------------------------------------------------------------
# 协议构建
# ---------------------------------------------------------------------------
def build_plaintext(ip, username, password, hostname, mac, tail="11111111"):
    """data= 明文（0x407310 拼接逻辑：8 段 + 固定尾串，'|' 分隔）。"""
    # 第 5 段：原客户端为 wsprintfW("%d|%s|%s", this指针, s1, s2)
    # this 指针每次进程运行不同（会话标识），服务器不校验具体值——用 0
    # s1/s2 为客户端内部 CString（时间相关），用空串最保守
    seg5 = "0||"
    parts = [ip, username, password, hostname, seg5, mac, tail]
    return "|".join(parts)

def make_payload(username, password, server_ip):
    """生成 (time_str, data_hex)——密钥即 &time= 值。"""
    t = time.strftime("%H:%M:%S")
    pt = build_plaintext(local_ip(server_ip), username, password,
                         local_hostname(), local_mac())
    data = des_ecb_encrypt(pt.encode("ascii"), t.encode("ascii")).hex().upper()
    return t, data, pt

def build_request(server_ip, username, password, method="login",
                  language="1", debug="no"):
    t, data, pt = make_payload(username, password, server_ip)
    req = (
        f"GET /cgi/client_check?un={username}&mymethod={method}"
        f"&login_client=win32&language={language}&time={t}&data={data}"
        f"&debug={debug}& HTTP/1.0\r\n"
        f"HOST: {server_ip}:3080\r\n"
        f"Accept: www/source, text/html, video/mpeg, image/jpeg, image/x-tiff\r\n"
        f"Content-type: application/x-www-form-urlencoded\r\n"
        f"\r\n"
    )
    return req, t, data, pt

# ---------------------------------------------------------------------------
# 网络交互
# ---------------------------------------------------------------------------
OK_MAP = {
    "login":     "auth_ok",
    "keepalive": "keepalive_ok",
    "logoff":    "logoff_ok",
}

def send_request(server_ip, req, timeout=8):
    s = socket.create_connection((server_ip, 3080), timeout=timeout)
    try:
        s.sendall(req.encode("ascii"))
        chunks = []
        while True:
            b = s.recv(4096)
            if not b:
                break
            chunks.append(b)
        return b"".join(chunks).decode("ascii", "replace")
    finally:
        s.close()

def do_method(server_ip, username, password, method, verbose=True):
    req, t, data, pt = build_request(server_ip, username, password, method)
    if verbose:
        print(f"[*] plaintext : {pt}")
        print(f"[*] time/key  : {t}")
        print(f"[*] data=     : {data[:32]}...({len(data)} hex chars)")
        print(f"[*] request   :\n{req}")
    resp = send_request(server_ip, req)
    if verbose:
        print(f"[*] response  :\n{resp}")
    expect = OK_MAP[method]
    ok = expect in resp
    print(f"[{'+' if ok else '!'}] {method} -> {'OK' if ok else 'FAILED'} "
          f"(expect {expect!r})")
    return ok

def keepalive_loop(server_ip, username, password, interval=20, max_fail=3):
    """保活循环：复刻原客户端状态机
    （'online is 1,off_num:%d,keepalive now' / 'over %d times unreceive data,reauth now'）。"""
    fails = 0
    n = 0
    while True:
        n += 1
        try:
            ok = do_method(server_ip, username, password, "keepalive",
                           verbose=False)
            fails = 0 if ok else fails + 1
            stamp = time.strftime("%H:%M:%S")
            print(f"[{stamp}] keepalive #{n}: {'ok' if ok else 'no-response'}")
        except OSError as e:
            fails += 1
            print(f"[!] keepalive #{n} network error: {e}")
        if fails >= max_fail:
            print(f"[!] over {max_fail} times unreceive data, reauth now")
            if do_method(server_ip, username, password, "login", verbose=False):
                fails = 0
            else:
                print("[!] reauth failed, retrying in next cycle")
        time.sleep(interval)

# ---------------------------------------------------------------------------
# 自检（离线）
# ---------------------------------------------------------------------------
def selftest():
    # DES NBS KAT
    kat = _des_block(b"\x00" * 8, subkeys(b"\x00" * 8))
    assert kat.hex().upper() == "8CA64DE9C1B123A7"
    print("[+] DES NBS KAT passed (8CA64DE9C1B123A7)")
    # 请求构建 roundtrip
    req, t, data, pt = build_request("10.10.94.1", "2202160228", "169332", "login")
    rt = des_ecb_decrypt(bytes.fromhex(data), t.encode("ascii")).decode("ascii")
    assert rt == pt
    print(f"[+] request build OK; plaintext = {pt!r}")
    print(f"[+] time key = {t!r}  data = {data}")
    print(f"\n{req}")
    return 0

def main():
    ap = argparse.ArgumentParser(
        description="冰川上网客户端替代认证工具（协议逆向 reimplementation）")
    ap.add_argument("--server", default="10.10.94.1", help="认证网关 IP（默认 10.10.94.1）")
    ap.add_argument("--un", help="用户名（学号/工号）")
    ap.add_argument("--pwd", help="密码")
    ap.add_argument("--interval", type=int, default=20, help="keepalive 间隔秒数")
    ap.add_argument("--selftest", action="store_true", help="离线自检（不联网）")
    ap.add_argument("method", nargs="?", choices=["login", "keepalive", "logoff"],
                    help="认证动作")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.method:
        ap.print_help()
        return 1
    if not args.un or not args.pwd:
        print("[!] 需要 --un 和 --pwd（或先运行 --selftest 验证协议层）", file=sys.stderr)
        return 1

    if args.method == "keepalive":
        keepalive_loop(args.server, args.un, args.pwd, args.interval)
        return 0
    ok = do_method(args.server, args.un, args.pwd, args.method)
    return 0 if ok else 2

if __name__ == "__main__":
    sys.exit(main())
