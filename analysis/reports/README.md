# 冰川上网客户端（Glaclient v4.12）完整逆向报告

- 案例：glaclient-audit
- 报告日期：2026-08-27
- 分析方式：本地沙盒离线静态逆向（全程未执行任何样本）
- 分析对象：gcsetup.exe 安装器 + 安装目录全套文件
- 语言/工具链：C++（MFC 10.0，MSVC 2010），主逻辑位于伪装的 `mfc101f.dll`
- 厂商：冰川网络 Glacier Network（www.bingchuan.net），版权 2007–2016

---

## 一、执行摘要 / Executive summary

对"冰川上网客户端"win32 认证客户端的完整逆向共发现 **4 项确认漏洞**（其中 2 项组合构成
严重级凭据暴露链）与 2 项设计风险。客户端用于校园网/运营商网络的 Portal 认证（3080 端口），
以管理员权限常驻运行。

最核心的发现是**认证协议的加密形同虚设**：`&data=` 载荷使用标准 DES-ECB，但**密钥就是
同一条 URL 里明文传输的 `&time=HH:MM:SS` 参数**。任何能抓到该 GET 请求的人（同一交换
网络、ARP 欺骗、代理/网关侧）都可以零成本实时解出用户名与密码明文——协议自带的"每秒
变化密钥"设计（密钥=当前时间）不构成任何防护，反而给人安全的错觉。

其次，"记住密码"功能将密码以静态密钥 0x522 的可逆编码写入 `config.ini`，任何本地进程
（包括低权限恶意软件）都可读取还原。

安装器与卸载器经反编译确认为 Thraex Software Astrum InstallWizard（未注册共享版）的
标准官方组件，**未发现供应链/捆绑恶意行为**；客户端主体亦未发现后门、隐蔽外联或数据
窃取行为——风险集中在弱密码学与明文传输，而非恶意植入。

---

## 二、样本身份 / Sample identity

| 文件 | 大小 | SHA-256 | 角色 |
|---|---|---|---|
| gcsetup.exe | 3,661,775 | abe044b3…d0b52b8 | 安装包（Astrum InstallWizard） |
| Glaclient.exe | 32,256 | 7a339285…e119a99c | 启动器（32KB，MFC GUI） |
| mfc101f.dll | 570,880 | b0520f94…62bc0e8a | **真实客户端主体**（伪装成 MFC DLL） |
| pkjiobcbzxzvbbccdrlr.exe | 570,880 | b0520f94…62bc0e8a | mfc101f.dll 的**逐字节副本**（随机名进程） |
| Uninstall.exe | 112,303 | 529b4f68…376555d9 | Astrum 官方卸载器 |
| Packet.dll | 96,784 | 6b19cffa…04e1d77a | WinPcap 用户层抓包库 |
| mfc100u.dll / msvcr100.dll | 4.4MB / 774KB | — | VC++ 2010 运行库（正版依赖） |

- 客户端核心：`Login` v4.12（PDB 路径 `\4.12\Release\Login.pdb`，类 CLoginApp/CLoginDlg）
- 升级通道：http://www.bingchuan.net/upgrade/glaclient/glaclient.txt

---

## 三、已验证事实 / Verified facts

### 3.1 进程隐藏机制（已证实）

Glaclient.exe 导入 `CopyFileW` + `ShellExecuteW`，manifest 要求 `requireAdministrator`；
启动时把 mfc101f.dll 复制为随机字母名 exe 并执行（目录中留存的
pkjiobcbzxzvbbccdrlr.exe 与 mfc101f.dll SHA-256 完全一致即为铁证）。

### 3.2 HTTP 认证协议（端口 3080，明文）

请求格式（mfc101f.dll .rdata 0x40f684–0x40f79c）：

```http
GET /cgi/client_check?un=<用户名>&mymethod=<m>&login_client=win32&language=<l>
    &time=<HH:MM:SS>&data=<DES密文大写hex>&debug=<g>& HTTP/1.0
Host: <server_ip>:3080
Accept: www/source, text/html, video/mpeg, image/jpeg, image/x-tiff
Content-type: application/x-www-form-urlencoded
```

`mymethod` 取值表（字符串引用逐一确认）：

| mymethod | 用途 | 期望响应 |
|---|---|---|
| `login` | 登录认证 | `auth_ok` / `auth error` |
| `keepalive` | 在线保活 | `keepalive_ok` |
| `logoff` | 登出 | `logoff_ok` / `other error` |

### 3.3 保活/重认证状态机

字符串证据：`online is 1,off_num:%d,keepalive now`、`samed network error,reauth now`、
`over %d times unreceive data,reauth now` —— 在线轮询 + 失败计数重认证。

### 3.4 单网卡限制的来源

导入 `IPHLPAPI.DLL`（GetAdaptersInfo 系列）+ 字符串 `UsedMac`/`RealMac`/
`ChoosedNetCard` —— 客户端枚举网卡/MAC 做绑定校验（README 声称的单网卡认证限制）。

---

## 四、密码学算法完整恢复 / Recovered algorithms

### 4.1 `&data=` 载荷（在线协议）

```text
key     = time_str "HH:MM:SS" 的 8 ASCII 字节（与 &time= 参数同值！）
cipher  = DES-ECB(plaintext, key)，零填充至 8 字节倍数
data    = uppercase hex(cipher)
明文格式 ≈ "用户名|密码[|主机名]" （长度 1–3 个 DES 块）
```

DES 函数地图（mfc101f.dll，image base 0x400000）：

| VA | 功能 |
|---|---|
| 0x40a760 | 密钥编排：64 key bits → PC1（表 @0x410738） |
| 0x40a820 | 16 轮：C/D 循环左移（shifts @0x4107a0）+ PC2（表 @0x410770）→ 16×48bit 子密钥 |
| 0x40aa00 | 加密块：IP（表 @0x4107b0）→ 16 轮 Feistel → 交换 → FP（表 @0x410a40） |
| 0x40ab80 | 解密块 |
| 0x40ad10 | 轮函数：E（表 @0x4107f0）⊕ K[i] → S 盒（@0x410820）→ P（表 @0x410a20）→ ⊕L |
| 0x40b300 / 0x40b440 | ECB 加/解密包装（零填充，输出 ctx+0x6eb / ctx+0x26eb） |
| 0x40b280 | bit → 大写 hex 字符串 |

验证：全部 8 张表（IP/E/P/FP/PC1/PC2/S/SHIFTS）与 FIPS 46 逐字节一致
（`scripts/des_tables_check.py`）；实现通过 NBS 标准测试向量
`DES(0,0)=8CA64DE9C1B123A7`（`scripts/des_data_codec.py`）。

### 4.2 `[KeepPassword]` 本地存储

存储格式：`config.ini` `[KeepPassword]` 节，`key=用户名`，`value=密文`（大写 A–Z，
长度=2×明文长）。

算法（反汇编自 mfc101f.dll 0x405020 编码 / 0x405190 解码，种子 0x522 读写一致）：

```text
state = 0x522 (1314)
对每个明文字符 c（UTF-16）：
    v   = c XOR (state >> 8)                       # 16 位
    state = (0x58bf - ((v & 0xFF) + state) * 0x3193) mod 0x10000
    密文 += chr('A' + v // 26) + chr('A' + v % 26)  # Base-26 双字母
```

实测解密（现场 config.ini，roundtrip 编码验证 100% 一致）：

| 用户名 | 密文 | 明文密码 |
|---|---|---|
| 2202160228 | CAIUGEGICXEK | 169332 |
| 2205120148 | CBFQBHHNIKAB | 025519 |

---

## 五、漏洞清单 / Vulnerability findings

### VULN-01 认证凭据弱加密且密钥随文明文传输（严重）

- **CWE**：CWE-327（使用已破解/有风险的密码算法）、CWE-322（密钥管理与消息非独立交换）
- **位置**：mfc101f.dll（函数地图见 4.1 节）
- **详情**：
  1. `&data=` 为 DES-ECB 密文的大写十六进制（NBS KAT 验证为教科书 DES）。
  2. DES 密钥 = 8 字节 ASCII 时间串 `"HH:MM:SS"`，**同一请求的 `&time=` 参数即为该
     密钥的明文**。
  3. ECB 模式 + 短明文：相同前缀产生相同密文块，泄露结构信息。
  4. 实际密钥空间仅一天 86400 个时间值且明文同传——攻击者无需穷举。
- **影响**：同一二层网络内的任何主机（共享网络/ARP 欺骗）、链路中间设备、代理控制者
  均可实时还原任意用户的账号与密码。
- **POC**：`scripts/des_data_codec.py`：

  ```python
  # sniffed: ...&time=08:05:33&data=47F1A2C33B09E7D5A1C4F6B2D8E09377
  decrypt_data("47F1A2C33B09E7D5A1C4F6B2D8E09377", "08:05:33")
  # -> b'2205120148|025519|...'  (用户名|密码|主机名)
  ```

- **修复**：迁移 TLS 1.2+；凭据决不能使用请求内可推导的密钥加密；采用 HMAC 或
  挑战-响应（服务器下发 nonce）。

### VULN-02 HTTP 明文认证通道（高）

- **CWE**：CWE-319（明文传输敏感信息）
- **位置**：mfc101f.dll .rdata 0x40f684–0x40f79c
- **详情**：认证/保活/登出全部走明文 GET；除 `data=`（可解）外用户名、时间、语言等
  全部明文，请求无完整性保护。
- **修复**：见 VULN-01（TLS 同时解决）。

### VULN-03 本地"记住密码"可逆存储（高）

- **CWE**：CWE-916（口令使用可逆变换存储）、CWE-312（敏感信息明文存储）
- **位置**：mfc101f.dll 编码 0x405020 / 解码 0x405190
- **详情**：见 4.2 节；静态密钥 0x522 硬编码，任何本地进程可离线还原明文口令。
  校园网口令常与统一身份认证复用，存在横向扩散风险。
- **POC**：`scripts/keep_password_codec.py`（实测解出两账户明文，见 4.2 表）。
- **修复**：默认不落盘；如必须记忆用 Windows DPAPI/Credential Manager；公共机器禁用。

### VULN-04 管理员权限常驻 + 进程伪装规避治理（中）

- **CWE**：CWE-250（非必要特权执行）、CWE-1036（伪装可信资源名）
- **位置**：Glaclient.exe（manifest requireAdministrator，CopyFileW/ShellExecuteW）
- **详情**：主体伪装为 `MFC101F.DLL`（非微软真实模块名），运行期落地随机 14–20 位
  小写字母名 EXE，管理权限常驻。基于进程名的防火墙/白名单/清点全部失效（README
  "无从下手"即为设计意图）。单一提权进程承载全部逻辑，放大 VULN-01/03 爆炸半径。
- **修复**：最小权限拆分（网络/抓包服务化）；停止伪装与随机进程名；升级签名校验。

### RISK-01 无完整性保护的升级检查（设计风险，待动态验证）

- 升级 URL `http://www.bingchuan.net/upgrade/glaclient/glaclient.txt` 为明文 HTTP。
  若更新无签名校验，中间人可投毒升级响应，配合管理员权限形成 RCE 链。

### RISK-02 MAC/单网卡绑定绕过面（设计风险）

- MAC 为客户端自报字段且置于可篡改的明文 GET 中，绑定强度存疑；应改为服务器侧
  会话特征绑定。

---

## 六、安装器与卸载器结论（无恶意）

| 文件 | 结论 | 证据 |
|---|---|---|
| gcsetup.exe | Astrum InstallWizard（Thraex Software）安装器，**未注册共享版** | manifest `ThraexSoftware.AstrumInstallWizard.AstrumInstaller`；字符串 "created using unregistered shareware version of Astrum InstallWizard"；2004-04-17 编译（MSVC6） |
| Uninstall.exe | Astrum 官方卸载器，行为干净 | 2004-03-05 编译；导入仅文件/注册表清理 API（RegDeleteKeyA/MoveFileExA/RemoveDirectoryA）；字符串 `http://www.thraexsoftware.com`、`Uninstallation information corrupt. Aborting.`；**无任何网络 API** |

补充说明：

- gcsetup.exe = 0x2d600 前的标准 PE stub（导入 SHFileOperationA、
  AdjustTokenPrivileges、打印 API，向导引擎特征）+ 3,475,919 字节 overlay。overlay
  前 0x5214 字节为明文多语言安装向导脚本（`<LangID=n>` 标记，30+ 语言界面），其后为
  压缩文件数据块（无明文文件名表）。
- stub 中 `"<ResourceDir>\3rd-party\Downloader.exe" /download /url "%s"` 与
  `" /q:a /c:"dasetup.exe /q /n""` 为 Astrum 引擎固有的组件下载与 .NET 静默安装参数；
  本包内未发现实际启用（无 dasetup 组件、无明文远程 URL）。
- zip 内 2026 年时间戳（config.ini 2026-08-27、目录当天打包）为**现场采集时间**，
  非编译时间；PE 编译时间 2004（安装器）/2015（客户端主体）与发布史吻合，
  "Uninstall.exe 2026 新编译"的怀疑排除。
- `.delete_on_reboot`/`wininit.ini` 为 Astrum 标准延迟删除机制。

---

## 七、推断与置信度 / Inference and confidence

| 推断 | 置信度 | 依据 |
|---|---|---|
| 随机名 exe = mfc101f.dll 副本，Glaclient 是投递器 | 高 | 哈希一致 + CopyFileW/ShellExecuteW 导入 |
| `&data=` 为 DES-ECB，密钥=`&time=` 参数 | 高 | 8 张表 FIPS 一致 + NBS KAT + 密钥生成链反汇编 |
| 认证为 GET + 查询串（非 POST body） | 高 | 0x40f684 "GET" + "client_check?" + "& HTTP/1.0" |
| KeepPassword 算法及种子 0x522 | 高 | 双函数反汇编 + roundtrip 验证 + 实测解密成功 |
| gcsetup.exe 为 Astrum 安装器（无恶意） | 高 | manifest + 未注册共享版字符串 + 导入表 |
| RISK-01 升级投毒可行 | 中 | 升级 URL 明文 HTTP，升级代码路径未穷尽 |

---

## 八、证据与工件索引 / Evidence index

| 工件 | 说明 |
|---|---|
| `scripts/des_data_codec.py` | DES `&data=` 编解码器（NBS KAT + roundtrip 通过） |
| `scripts/des_tables_check.py` | 8 张 DES 表与 FIPS 46 一致性验证 |
| `scripts/keep_password_codec.py` | KeepPassword 编解码器（roundtrip 100%） |
| `scripts/gcsetup_pe.py` / `gcsetup_overlay.py` / `gcsetup_script.py` | 安装器结构/overlay/脚本分析 |
| `scripts/uninstall_pe.py` | 卸载器 PE 分诊 |
| `scripts/find_login.py` / `find_refs2.py` / `find_refs3.py` | mymethod/字符串引用定位 |
| `scripts/iat_map.py` | mfc101f.dll IAT 槽位→符号映射 |
| `scripts/dump_strings.py` / `dump_block.py` / `decode_bruteforce.py` | 字符串/内存块导出、排除法破密 |
| `disasm_text.txt` | mfc101f.dll .text 全量反汇编（15,672 行） |
| `reports/analysis-report.md` | 前期分析报告 |
| `reports/vulnerability-report.md` | 正式漏洞报告（本报告的漏洞详版） |
| `triage/*.triage.md` | 样本分诊 |

---

## 九、修复优先级 / Remediation priorities

1. **立即**：认证通道迁移 TLS（消除 VULN-01/02/被动抓包面）；废弃"密钥=时间参数"设计。
2. **短期**：本地凭据改 DPAPI 或禁用记住密码（VULN-03）；升级通道 HTTPS+签名（RISK-01）。
3. **中期**：去管理员常驻、停止 DLL 伪装与随机进程名（VULN-04）；服务器侧会话绑定
   替代客户端自报 MAC（RISK-02）。

---

## 十、总体结论

客户端**无后门/无恶意植入**，安装器/卸载器为第三方标准组件；风险全部集中在**弱密码学
设计**：最坏情况下，同网络的攻击者抓一个 GET 请求即可还原任意用户明文口令，配合本地
可逆存储形成完整凭据暴露链。

> 分析范围与限制：本报告基于纯静态逆向（含完整 DES/流密码实现恢复与标准测试向量验证）；
> 未执行样本、未验证服务器侧行为与升级代码完整路径（RISK-01 定级待动态验证）。
