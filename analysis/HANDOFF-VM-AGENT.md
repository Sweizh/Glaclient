# 冰川上网客户端替代工具 · 虚拟机 Agent 交接文档

> **本文档用途**：交给测试虚拟机（Windows）里的 TraeCode CLI Agent，使其在无需历史对话上下文的情况下接管项目。
> **生成**：2026-08-27 · **v2 改版**：2026-09（方案变更：OpenWrt 三 VM → 单 Win VM + SOCKS5 代理阵列）
> **上游仓库**：https://github.com/Sweizh/Glaclient （Agent 进场第一件事：clone 该仓库，见 §8）

---

## 0. 一句话使命

为校园网"冰川上网客户端"（Glaclient v4.12）开发 **Windows 开源替代软件**：单机多账号并发认证（每账号绑定一块独立虚拟网卡 = 独立 IP），并为**每个账号提供独立 SOCKS5 代理端口**（`IP:1081` 走账号 A、`:1082` 走账号 B……），实现多账号带宽叠加，替代现网 Win11 虚拟机跑原客户端 + CCproxy 的组合。

---

## 1. 已完成工作（云端沙盒阶段，全部已验证）

### 1.1 逆向成果（实锤，经数学验证）

样本：`gcsetup.exe` 安装器 + `mfc101f.dll`（客户端核心，伪装成 MFC 模块，实际是认证主程序，运行时被复制为随机名 EXE——进程隐藏机制）。

**完整协议规范（逆向自 mfc101f.dll，image base 0x400000）**：

| 要素 | 内容 | 逆向依据 |
|---|---|---|
| 传输 | 明文 HTTP/1.0，`10.10.94.1:3080` | 抓包观察 + 代码 |
| 请求 | `GET /cgi/client_check?un=<用户名>&mymethod=<方法>&login_client=win32&language=1&time=HH:MM:SS&data=<大写HEX>&debug=no& HTTP/1.0` | 0x407xxx 请求构建函数 |
| 方法 | `mymethod` = `login` / `keepalive` / `logoff` | 字符串引用 |
| 加密 | `data=` = **标准 DES-ECB**（明文零填充至 8 字节块），输出大写十六进制 | 0x40a760–0x40b440，8 张置换表与 FIPS 46 逐字节一致 |
| 密钥 | 8 字节 ASCII = **同一 URL 里明文的 `&time=` 值**（`HH:MM:SS`） | 0x40b300 调用点 + 时间格式串 `%02d:%02d:%02d` |
| 明文结构 | `ip\|用户名\|密码\|主机名\|0\|\|\|MAC\|11111111`（竖线分隔 9 段） | 0x407310 |
| 成功判定 | 响应含 `auth_ok` | 响应解析函数 |
| 保活 | 20 秒一次 keepalive，连续 3 次无响应自动重新认证 | 调试串 + 状态机 |
| 记住密码 | config.ini `[KeepPassword]`，XOR 流（种子 0x522）+ Base-26 双字母编码 | 0x405020/0x405190，已实测解密 |

**安全结论**（已写入漏洞报告）：DES 密钥随请求明文传输，抓包者可零成本实时解出账号密码；HTTP 明文通道；"密钥每秒变化"不构成防护。

### 1.2 已交付代码（仓库 `analysis/scripts/` 目录，全部可运行）

| 文件 | 作用 |
|---|---|
| `glaclient_reimpl.py` | ★ 核心引擎（Python）：DES、请求构建、AuthSession 多会话引擎、虚拟身份、netsh IP 别名（`--real-vnic`）、CLI。**Win 软件直接复用此模块** |
| `glaclient_ui.py` | tkinter 图形版（Windows 可用），多账号保存（accounts.json + 原客户端同款加密）。**Win 软件的 UI 底座** |
| `des_data_codec.py` | `&data=` DES 编解码器，内置 NBS 官方测试向量自检 |
| `keep_password_codec.py` | config.ini 记住密码解密 |
| `des_tables_check.py` | DES 8 表 FIPS 46 一致性验证 |

**验证状态**：DES 通过 NBS KAT（`8CA64DE9C1B123A7`）；mock 网关 5 账号×5 虚拟网卡并发 e2e 通过。**但从未接触真实网关**——这正是本阶段任务。

---

## 2. 现网环境（生产区 · 一律不动）

来源：https://blog.sweizh.top/post/lab-nat（实验室网络搭建记录）

| 设备 | IP | 角色 | Agent 权限 |
|---|---|---|---|
| Win11 虚拟机 | 10.10.94.21 | 冰川认证 + ClashVerge(7897) + CCproxy(1080) + 达芬奇项目库 | **禁止一切操作** |
| iStoreOS 虚拟机 | 10.10.94.40 | 团队网关 V2rayA 分流，全实验室依赖 | **禁止一切操作** |
| 小米 CR8806 | 10.10.94.30 | ImmortalWrt 无线发射（MT7621） | **禁止一切操作** |
| 飞牛 NAS 宿主机 | 10.10.94.31 | fnOS + OVS + 全部虚拟机 | 仅通过其虚拟机界面**新建/配置测试 VM**，不动现有配置 |
| 校园网关 | 10.10.94.1:3080 | Portal 认证，单账号限速 ~100Mbps | 测试对象 |

**关键现网事实**：团队全部流量经代理从 10.10.94.21 的认证 IP 出去 = 网关按 IP 认证、不限制 IP 背后连接数的现成实证。全团队共享单账号 100Mbps 是本项目要解决的痛点。

---

## 3. 测试隔离区（用户新建，Agent 工作范围）

**只此一台 VM**（阶段复用：金标准抓包 → 开发机 → 软件载体）：

| 项目 | 规格 |
|---|---|
| 系统 | Windows 10 LTSC 21H2 或 Win11 IoT 企业版 LTSC |
| 虚拟化 | 飞牛 KVM，2C2G/40G 起步 |
| 网卡 | **主网卡 1 块**（bridge 校园网，DHCP 拿 10.10.94.x）+ **阶段 3 前由用户在飞牛界面加 N 块 virtio 网卡**（N=账号数，≤8） |
| 预装 | 原版冰川客户端（阶段 1 用）→ Python 3.12 + Git + TraeCode CLI（阶段 2 起用） |

**为什么用多 vNIC 而非 netsh IP 别名**：每块 virtio 网卡独立 MAC + 独立 DHCP 取号，与"真实物联网卡插在网关上"完全等效；netsh 别名所有 IP 共享一个 MAC，若网关校验 MAC 唯一性会翻车。netsh 方案保留在 `glaclient_reimpl.py --real-vnic` 作为备选。KVM virtio 混杂模式默认放行，OVS 只做端口 MAC 学习，无障碍。

**网络要点**：
- 未认证时无外网。**Agent 的 API 流量走生产代理**：`HTTP_PROXY/HTTPS_PROXY=http://10.10.94.21:7897`，且必须 `NO_PROXY=10.10.94.1,10.0.0.0/8,localhost`。
- **铁律：认证请求绝不走代理**，必须直连 10.10.94.1:3080，否则测试作废且可能干扰生产认证。

**目标软件形态**（开发蓝本）：

```
Glaclient for Windows（Python + tkinter，PyInstaller 打包单 exe，需管理员/UAC）
├── 多账号管理（accounts.json，原客户端同款加密存储）
├── 认证引擎（复用 glaclient_reimpl.py：login/keepalive/logoff + 20s 保活状态机）
├── 网卡-账号绑定（枚举 vNIC → 每账号绑一块 → 严格 1 IP : 1 账号）
├── SOCKS5 代理阵列（新增核心）
│     监听 0.0.0.0:108N → 出站 bind 到账号 N 的 vNIC IP
│     域名解析走系统 getaddrinfo（DNS 从主 IP 出，网关放行）
│     RFC 1928 CONNECT（TCP）；UDP ASSOCIATE 不做
└── 状态监控（每账号认证状态/各端口流量）
```

**1 IP : 1 账号的等价性**（已与用户确认的结论）：网关无论按 IP 还是按账号限速，只要严格每 IP 挂一个账号，N 账号都是 N 份独立 100Mbps。要避免的只有错配（一 IP 多账号 = 白认证；一账号多 IP = 共享额度）。

---

## 4. 用户提供清单（收到后才开工）

```
[ ] Win 测试 VM：IP + 管理员账号密码（本机，Agent 所在）
[ ] VM 已拍快照（名字告知）
[ ] 阶段 1 前：原版冰川客户端已装好、能正常登录
[ ] 测试校园网账号：2 个左右（工/学号+密码，用户本人的，禁用团队日常账号）
[ ] 阶段 3 前：飞牛界面给 VM 加 N 块 virtio 网卡（N=账号数）并告知
```

---

## 5. 分阶段执行计划

### 阶段 1：金标准抓包对照（风险≈零）
1. 在 Win 测试 VM 本机起抓包（管理员 PowerShell，Win 自带）：
   ```powershell
   pktmon filter add gc -p 3080
   pktmon start --capture --pkt-size 0 -f C:\gc.etl
   # → 提示用户：在冰川客户端点一次"登录"（唯一人工步骤，约10秒）
   pktmon stop
   pktmon etl2pcapng C:\gc.etl -o C:\gc.pcapng   # Win11 新版为 pcapngfmt 子命令
   ```
   注意 `--pkt-size 0` 必加（默认 128 字节会截断 data=）。
2. 解析 GET 请求中 `time=` 与 `data=`；用 time 作 DES 密钥解密 data，与逆向明文结构逐字段比对；比对请求格式/headers/响应判定串。
3. 产出《金标准对照报告》：一致则逆向实锤；不一致则修正逆向实现后复测。

### 阶段 2：单账号真实网关实测（风险=正常登录一次）
1. VM 装 Python + Git + TraeCode CLI（API 走 §3 代理配置）。
2. 直连（禁代理）跑 `python analysis\scripts\glaclient_reimpl.py --server 10.10.94.1 --un <测试号> --pwd <密码> keepalive`：login → 数轮 keepalive → logoff。
3. 记录网关全部响应：成功串、错误码字典（密码错/重复登录/超时等）。
4. 产出协议验证结论。失败则对照阶段 1 抓包修正。

### 阶段 3：多账号 + 多 vNIC 探测（中风险，每步先报告待用户批准）
前提：用户已在飞牛给 VM 加 N 块 virtio 网卡，各拿到独立 10.10.94.x。
1. 逐账号绑定逐网卡认证（严格 1:1），观察网关反应。
2. 回答两个判决性问题：
   - 一个物理口背后认证多个 IP/MAC，网关放不放行？
   - 认证后从各 vNIC IP 出的流量是否真被独立放行？
3. iperf3 多连接测各出口独立带宽 → 叠加倍数实测。
4. 任何异常（认证被拒/IP 被封迹象）立即停止并报告。

### 阶段 4：软件开发与打包
1. `glaclient.pyw` 主程序：整合 `glaclient_reimpl.py` 引擎 + `glaclient_ui.py` 底座 + 新增 SOCKS5 阵列模块（§3 蓝本：监听 0.0.0.0、bind 出口 IP、系统 DNS、TCP CONNECT）。
2. **回归铁律**：mock 网关全流程回归（认证 + SOCKS5 转发 + 保活状态机）后才上真机。
3. PyInstaller `--onefile --uac-admin` 打包单 exe；GitHub Actions CI：tag → 自动构建 exe → GitHub Releases（附 sha256）。
4. 真机验证：N 账号认证 → 团队设备分别挂 `socks5://<VM_IP>:108N` → iperf3 实测各端口独立带宽。
5. 源码整理进开源仓库（§7）。

### 阶段 5：生产切换方案书（用户拍板后执行）
新认证 VM（或现 .21 平移）部署 Glaclient 软件 → 团队代理从 CCproxy 迁移到各 SOCKS5 端口（Clash 可挂上游继续规则分流）→ 回滚预案。完成后 Win11 生产机可卸冰川客户端与 CCproxy，仅留达芬奇库与 Clash。

---

## 6. 风险红线（任何阶段适用）

1. 生产区四台设备（§2）零操作；唯一例外：飞牛界面新建/配置测试 VM。
2. 认证流量永不走代理（§3 铁律）。
3. 多账号行为（阶段 3 起）每步先报告后执行；封号/违反校园网使用条款的风险归用户拍板。
4. 测试一律用用户提供的个人测试账号，绝不碰团队日常账号。
5. 真实账号、密码、抓包中的 PII 永不写入开源仓库；报告脱敏后提交。
6. 每个破坏性动作前确认测试 VM 快照存在。

---

## 7. 最终交付物清单

| 类别 | 内容 |
|---|---|
| 软件 | `Glaclient.exe`（单文件，含多账号认证 + SOCKS5 代理阵列 + tkinter 管理界面），GitHub Releases 分发 |
| 开源仓库 | GPL-3.0；结构：`src/`（主程序）、`socks5/`（代理模块）、`.github/workflows/build.yml`；README 中英双语，含安装/使用/风险声明 |
| 报告 | 金标准对照报告、网关行为字典、多账号探测结论、iperf3 叠加实测数据、生产切换方案书、故障排查手册 |
| 过程资产 | 抓包样本+解析脚本、mock 网关回归套件 |

**明确不交付**：原软件源码复刻、单连接叠加（用户已砍掉）、UDP ASSOCIATE（后续看需求）、网关服务端任何内容。

---

## 8. 仓库获取（Agent 进场第一步）

本文档单独交付；全部代码、脚本、逆向报告在 GitHub 仓库：

```
https://github.com/Sweizh/Glaclient
```

**校园网直连 GitHub 不通**，未认证的 Win VM 必须走生产代理 clone（这是代理唯一允许的用途之一）。

**⚠ 必须指定分支 `trae/agent-E6ukCg`**——默认 clone 拉的是 main，main 缺少关键提交（`glaclient_reimpl.py`、`glaclient_ui.py`、本文档等均在分支上，未合入 main）：

```powershell
$env:HTTPS_PROXY="http://10.10.94.21:7897"
git clone -b trae/agent-E6ukCg https://github.com/Sweizh/Glaclient
```

clone 后的关键内容：

```
Glaclient/
├── README.md                    # 逆向结论速览
└── analysis/                    # 逆向分析全套
    ├── HANDOFF-VM-AGENT.md      # 本文档（若未单独收到，从仓库读）
    ├── samples/                 # 原始样本：gcsetup.exe + 安装目录 zip（勿执行）
    ├── scripts/                 # 全部脚本（glaclient_reimpl.py 为核心引擎）
    └── reports/                 # 完整逆向报告（协议细节的权威来源）
```

Agent 开工自检（clone 完成后立即执行）：

```powershell
cd Glaclient\analysis
python scripts\des_data_codec.py   # 应输出 NBS KAT passed + roundtrip OK
```

不通过说明 clone 不完整或文件损坏，先解决再动。后续开发工作目录即 `Glaclient/`，所有新代码提交回该仓库（分支或 main，以用户指示为准）。

---

## 9. Agent 行为约定

- 收到本文档 + §4 凭据清单后：先走代理 clone 仓库（§8）并跑开工自检，再检查本机环境（Python/pktmon/网卡列表），最后进阶段 1。
- 每阶段结束出报告，等用户确认再进下一阶段（阶段 2→3 之间必须停）。
- 长任务（iperf3、打包）后台跑，会话断了下轮回收。
- 遇协议不符/网关异常/权限不足三类问题：停止、记录、报告，不猜测强推。
