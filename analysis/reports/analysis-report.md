# 冰川上网客户端（AuthGate win32 client）逆向分析报告

- 案例：glaclient-audit
- 分析日期：2026-08-27
- 样本来源：samples/（gcsetup.exe + 冰川上网客户端安装目录文件.zip）
- 分析方式：本地沙盒离线静态分析（未执行任何样本）

## 1. 样本身份 / Sample identity

| 文件 | 大小 | SHA-256 | 角色 |
|---|---|---|---|
| gcsetup.exe | 3,661,775 | abe044b3…d0b52b8 | 安装包（高熵，疑似 NSIS/Inno 打包，未深入） |
| Glaclient.exe | 32,256 | 7a339285…e119a99c | 启动器（32KB，MFC GUI） |
| mfc101f.dll | 570,880 | b0520f94…62bc0e8a | **真实客户端主体**（伪装成 MFC DLL） |
| pkjiobcbzxzvbbccdrlr.exe | 570,880 | b0520f94…62bc0e8a | mfc101f.dll 的**逐字节副本**（随机名进程） |
| Packet.dll | 96,784 | 6b19cffa…04e1d77a | WinPcap 用户层抓包库 |
| mfc100u.dll / msvcr100.dll | 4.4MB / 774KB | — | VC++ 2010 运行库（正版依赖） |

- 厂商：冰川网络 Glacier Network（www.bingchuan.net），版权 2007-2016
- 客户端核心：`Login` v4.12（PDB 路径 `\4.12\Release\Login.pdb`，类 CLoginApp/CLoginDlg）
- 升级通道：http://www.bingchuan.net/upgrade/glaclient/glaclient.txt

## 2. 已验证事实 / Verified facts

1. **进程隐藏机制（README 声称）已证实**：Glaclient.exe 导入 `CopyFileW` + `ShellExecuteW`，
   manifest 要求 `requireAdministrator`；启动时把 mfc101f.dll 复制为随机字母名 exe 并执行
   （目录中留存的 pkjiobcbzxzvbbccdrlr.exe 与 mfc101f.dll SHA-256 完全一致即为铁证）。
2. **HTTP 明文认证协议（端口 3080）**，请求格式（.rdata 0x40f684-0x40f79c）：
   ```http
   GET /cgi/client_check?&mymethod=<m>&login_client=win32&language=<l>&time=<t>&data=<d>&debug=<g>& HTTP/1.0
   HOST: <server_ip>:3080
   Accept: www/source, text/html, video/mpeg, image/jpeg, image/x-tiff
   Content-type: application/x-www-form-urlencoded
   ```
   响应关键字：`auth_ok` / `keepalive_ok` / `logoff_ok` / `auth error` / `other error`。
   README 中"密钥每秒变化"对应 `&time=` + `&data=`（时间戳参与加密，`pInfo->encrypt_type:%d` 表明多算法分支）。
3. **保活/重认证状态机**：`online is 1,off_num:%d,keepalive now`、
   `samed network error,reauth now`、`over %d times unreceive data,reauth now`。
4. **单网卡限制的来源**：导入 `IPHLPAPI.DLL`（GetAdaptersInfo 系列）+ 字符串 `UsedMac`/`RealMac`/
   `ChoosedNetCard` —— 客户端枚举网卡/MAC 做绑定校验（README 声称的单网卡认证限制）。
5. **本地密码存储加密已完全破解**（见第 3 节），config.ini `[KeepPassword]` 以用户名为 key。

## 3. KeepPassword 加密算法完整恢复 / Recovered crypto

存储格式：`[KeepPassword]` 节，`key=用户名`，`value=密文`（大写 A-Z，长度=2×明文长）。

算法（反汇编自 mfc101f.dll 0x405020 编码 / 0x405190 解码，种子 0x522 读写一致）：

```text
state = 0x522 (1314)
对每个明文字符 c（UTF-16）：
    v   = c XOR (state >> 8)                       # 16 位
    state = (0x58bf - ((v & 0xFF) + state) * 0x3193) mod 0x10000
    密文 += chr('A' + v // 26) + chr('A' + v % 26)  # Base-26 双字母
```

解码结果（roundtrip 编码验证 100% 一致）：

| 用户名 | 密文 | 明文密码 |
|---|---|---|
| 2202160228 | CAIUGEGICXEK | 169332 |
| 2205120148 | CBFQBHHNIKAB | 025519 |

解码脚本：`scripts/keep_password_codec.py`（含编码器与自校验）。

## 4. 推断与置信度 / Inference and confidence

| 推断 | 置信度 | 依据 |
|---|---|---|
| 随机名 exe = mfc101f.dll 副本，Glaclient 是投递器 | 高 | 哈希一致 + CopyFileW/ShellExecuteW 导入 |
| 认证为 GET + 查询串（非 POST body） | 高 | 0x40f684 "GET" + "client_check?" + "& HTTP/1.0" |
| `&data=` 为自定义对称加密载荷（含时间因子） | 中 | `encrypt_type` 分支 + README 每秒变密钥描述 |
| README"Wireshark 可见 http"= 本协议 3080 端口 | 中高 | 协议字段与 README 描述吻合 |
| gcsetup.exe 为安装器（打包） | 中 | 高熵前缀 + PE 结构，未反编译 |

## 5. 风险/漏洞候选 / Risk & vulnerability candidates

1. **本地密码可逆存储**（CWE-327/916）：混淆级"加密"，静态密钥 0x522 硬编码于二进制，
   任何拿到 config.ini 的进程可还原明文密码。
2. **HTTP 明文认证**（CWE-319）：3080 端口无 TLS，`data=` 是唯一机密性保护；
   若其加密不含服务器端挑战，则可重放。
3. **伪装 + 随机进程名**（防御规避）：主体伪装成 MFC101F.DLL（非微软真实模块名），
   运行期落地随机名 exe，绕过基于进程名的防火墙规则——README 的"无从下手"即此。
4. **requireAdministrator**：客户端以管理员权限常驻（抓包/网卡操作需要），放大上述风险。

## 6. 证据索引 / Evidence index

- 分诊 JSON/MD：`triage/*.triage.{json,md}`
- 反汇编导出：`disasm_text.txt`（.text 节，15,672 行）
- 关键函数：编码 0x405020 / 解码 0x405190（mfc101f.dll，VA 基址 0x400000）
- 关键字符串 VA：KeepPassword=0x40f0dc、GET=0x40f684、client_check=0x40f68c、
  :3080=0x40f700、auth_ok=0x40f8f0
- 脚本：`scripts/decode_bruteforce.py`（排除法）、`scripts/keep_password_codec.py`（最终算法）

## 7. 未完成事项 / Open items

- `&data=` 载荷的具体加密算法（需定位 encrypt_type 分支与加密函数）
- `mymethod` 取值表（login/keepalive/logoff 推测）
- gcsetup.exe 安装器内部结构
- Uninstall.exe（2026 年新编译，时间戳异常，值得抽查）
