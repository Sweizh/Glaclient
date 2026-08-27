# 冰川上网客户端（Glaclient v4.12）逆向分析仓库

对"冰川上网客户端"win32 Portal 认证客户端的完整离线静态逆向分析案例。
样本：`gcsetup.exe` 安装器 + `冰川上网客户端安装目录文件.zip`（安装目录全套文件）。

- 厂商：冰川网络 Glacier Network（www.bingchuan.net），版权 2007–2016
- 客户端核心：`Login` v4.12（PDB 路径 `\4.12\Release\Login.pdb`）
- 分析方式：本地沙盒离线静态逆向（全程未执行任何样本）
- **完整报告：[cases/bcswkhd-audit/reports/README.md](cases/bcswkhd-audit/reports/README.md)**

---

## 原始 README（现场观察，保留存档）

> 系统限制：仅支持 Windows 平台
>
> 网卡限制：必须保持单网卡环境才能认证，这直接导致通过 Windows 网络共享功能实现其他设备上网的方法直接报废；
>
> 进程隐藏：每次启动会生成随机英文字符名的 exe 文件，想通过防火墙隔离都无从下手；
>
> 动态认证：虽然是Windows程序，但是通过Wireshark抓包可以发现程序认证设备使用的是http协议，向10.10.94.1的网关发送认证，认证的密钥每秒都在变化，想模拟请求绕开客户端也不现实。

## 逆向验证结论（对照原始观察）

| 原始观察 | 逆向验证结果 |
|---|---|
| 进程隐藏：随机英文字母名 exe | **已证实**：32KB 启动器 Glaclient.exe（`requireAdministrator`）将 `mfc101f.dll` 复制为随机名 EXE 执行；两者 SHA-256 完全一致（`b0520f94…`），伪装成 MFC101F.DLL（非微软真实模块名） |
| 网卡限制：单网卡 | **已证实**：导入 IPHLPAPI（GetAdaptersInfo）+ `UsedMac`/`RealMac`/`ChoosedNetCard`，MAC 绑定校验 |
| 动态认证：密钥每秒变化，无法模拟 | **已证伪并实现替代客户端**：认证为 `GET /cgi/client_check?...`（端口 3080 明文 HTTP），`&data=` 为 DES-ECB 密文，**密钥就是同一 URL 里明文传输的 `&time=HH:MM:SS` 参数**。基于此已实现完整替代认证工具 `scripts/glaclient_reimpl.py`（见下文"替代认证客户端"） |
| HTTP 协议（Wireshark 可见） | **已证实**：3080 端口明文 HTTP/1.0，完整请求格式已恢复（见报告第三节） |

## 关键发现速览

1. **VULN-01（严重）** DES 密钥随文明文传输——`&data=` 用标准 DES-ECB，密钥 = 请求内明文 `&time=` 参数
2. **VULN-02（高）** HTTP 明文认证通道（CWE-319）
3. **VULN-03（高）** "记住密码"以静态密钥 0x522 可逆存储于 config.ini（实测解出两账户明文口令）
4. **VULN-04（中）** 管理员权限常驻 + DLL 伪装/随机进程名（CWE-250/1036）
5. **安装器/卸载器**：Astrum InstallWizard（Thraex Software）官方组件，无恶意行为
6. **总体**：无后门/无恶意植入，风险集中于弱密码学设计

## 仓库结构

```text
├── README.md                          # 本文件
├── gcsetup.exe                        # 样本：安装器（Astrum InstallWizard）
├── 冰川上网客户端安装目录文件.zip       # 样本：安装目录全套
├── bcswkhd/                           # 原始样本的另一工作副本（勿改）
└── cases/bcswkhd-audit/               # 逆向分析案例
    ├── reports/README.md              # ★ 完整逆向报告（入口）
    ├── reports/vulnerability-report.md # 正式漏洞报告
    ├── reports/analysis-report.md     # 前期分析报告
    ├── scripts/                       # 18 个分析/解密脚本（全部可运行）
    │   ├── glaclient_ui.py            # ★★ 图形界面（多账号管理，Windows 支持）
    │   ├── glaclient_reimpl.py        # ★★ 替代认证客户端（登录/保活/登出）
    │   ├── des_data_codec.py          # ★ &data= DES 编解码器（NBS KAT 验证）
    │   ├── keep_password_codec.py     # ★ KeepPassword 编解码器
    │   └── des_tables_check.py        # DES 8 表 FIPS 46 一致性验证
    ├── artifacts/extracted/           # 样本解包（含 config.ini 密文证据）
    ├── triage/                        # 样本分诊
    ├── notes/                         # 假设/沙盒规则/决策记录
    └── disasm_text.txt                # mfc101f.dll 全量反汇编（15,672 行）
```

## 快速验证（解密演示）

```bash
# DES &data= 编解码（抓包 -> 明文）
python3 cases/bcswkhd-audit/scripts/des_data_codec.py
# 输出: NBS KAT passed + roundtrip OK（明文格式 ≈ "用户名|密码|主机名"）

# 本地记住密码解密（config.ini -> 明文口令）
python3 cases/bcswkhd-audit/scripts/keep_password_codec.py
```

## 替代认证客户端（逆向 reimplementation）

`scripts/glaclient_reimpl.py` 是基于上述逆向结果实现的**完整替代认证工具**，
可脱离原客户端（无需管理员权限、无需伪装进程、任意网卡环境）完成 Portal 认证：

```bash
# 离线自检（验证 DES + 请求构建，不联网）
python3 glaclient_reimpl.py --selftest

# 登录
python3 glaclient_reimpl.py --server 10.10.94.1 --un <用户名> --pwd <密码> login

# 登录 + 自动保活（复刻原客户端状态机：连续 3 次无响应自动重认证）
python3 glaclient_reimpl.py --server 10.10.94.1 --un <用户名> --pwd <密码> keepalive --interval 20

# 登出
python3 glaclient_reimpl.py --server 10.10.94.1 --un <用户名> --pwd <密码> logoff
```

与原客户端行为对照：明文结构 `ip|user|pwd|host|0|||MAC|11111111`（0x407310）、
密钥 = `&time=` 同值（DES-ECB）、`mymethod` 三态路由、keepalive 失败重认证阈值
（`over %d times unreceive data,reauth now`）均逐函数逆向恢复并通过 roundtrip 验证。

## 图形界面版（多账号 + 多虚拟网卡并发 + Windows 支持）

`scripts/glaclient_ui.py` 提供完整 GUI（Python 标准库 tkinter，**零第三方依赖**，
Windows 官方 Python 安装包自带 tkinter）：

- **多账号管理**：增/删/改/保存，列表点选即载入；密码以原客户端 `[KeepPassword]`
  同款算法（种子 0x522）加密存储于同目录 `accounts.json`
- **自定义虚拟网卡数量**：一键批量生成 N 个虚拟网卡
  （02 开头本地管理 MAC + 顺序 IP + 主机名），自动分配给未绑定的账号；
  也可在账号表单手工填写（含随机 MAC 按钮）
- **多网卡多账户并发认证**：每账号独立 `AuthSession` 线程同时登录/保活，
  会话面板实时显示各会话（账号/网卡/状态/最后活动），
  支持「全部登录 / 全部登出」
- **两种虚拟网卡模式**：
  - **明文模式**（免权限，协议研究用）：认证明文中的 ip/host/MAC
    替换为虚拟身份，但数据包源 IP 仍是物理网卡主 IP
  - **OS 插卡模式**（需管理员/root，等效插实体物联网卡）：经
    `VirtualNicManager` 在操作系统层创建**真实接口**——Linux 用
    `macvlan`（独立接口+独立 MAC，与插一张实体卡无异），Windows 用
    `netsh` 给物理网卡加 IP 别名（网关看到独立 ARP 条目），macOS 用
    `ifconfig alias`；每个会话 socket **bind 到各自虚拟 IP** 发包，
    **网关看到的源 IP/MAC 就是虚拟身份**；退出自动删除接口
- **复刻原客户端状态机**：连续 3 次无响应自动重认证，线程运行不卡界面
- **跨平台环境采集**：Linux 读 `/sys/class/net`，Windows/macOS 走 `uuid.getnode()`
- **实时日志**：每次请求的时间密钥、响应判定结果全可见
- Windows 上推荐 `pythonw glaclient_ui.py`（无控制台窗口）或用
  `pyinstaller --onefile --noconsole glaclient_ui.py` 打包成单个 exe

```bash
python3 scripts/glaclient_ui.py     # Windows: python glaclient_ui.py

# CLI 多账号并发（明文虚拟网卡模式）
python3 scripts/glaclient_reimpl.py --multi scripts/accounts.json \
    --vnic-ip-prefix 10.10.94 --vnic-start 100

# CLI 多账号并发（OS 插卡模式：数据包源 IP = 虚拟 IP，需管理员/root）
# Windows（管理员）：netsh IP 别名；Linux（sudo）：macvlan 独立 MAC
python3 scripts/glaclient_reimpl.py --multi scripts/accounts.json --real-vnic
sudo  python3 scripts/glaclient_reimpl.py --multi scripts/accounts.json --real-vnic
```

> 插卡模式说明：Linux macvlan 创建的接口拥有独立 MAC+IP，网关完全将其
> 视为一台独立设备（与插实体物联网卡等效）；Windows 为物理网卡 IP 别名
> （网关见独立 ARP 条目，源 MAC 为物理网卡——Windows 单网卡多 MAC 需
> NDIS 驱动级方案）。沙盒验证：bind 源 IP 经服务器侧 `getpeername()`
> 实测确认生效；macvlan/netsh/ifconfig 命令三平台逐一验证。

## 样本哈希

| 文件 | SHA-256 |
|---|---|
| gcsetup.exe | abe044b3b0f16327609ec3fa49208b05cf55053c8fcff5e75ffe7b894d0b52b8 |
| mfc101f.dll = pkjiobcbzxzvbbccdrlr.exe | b0520f94…（逐字节一致，伪装铁证） |
| Glaclient.exe | 7a339285…e119a99c |
| Uninstall.exe | 529b4f68287b93b417829f2342a86e4ae5de0dd636783dcd2b32ee85376555d9 |

---

> 分析范围与限制：纯静态逆向；未执行样本、未验证服务器侧行为与升级代码完整路径。
> 本仓库仅用于授权安全研究/教学用途。
