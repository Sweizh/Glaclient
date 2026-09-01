# 冰川上网客户端替代工具 · 虚拟机 Agent 交接文档

> **本文档用途**：交给测试虚拟机（Debian）里的 TraeCode CLI Agent，使其在无需历史对话上下文的情况下接管项目。
> **生成时间**：2026-08-27 · 基于完整离线静态逆向 + 多轮方案讨论
> **上游仓库**：本目录（cases/bcswkhd-audit）需随本文档一起拷入 Debian VM

---

## 0. 一句话使命

为校园网"冰川上网客户端"（Glaclient v4.12）开发开源 OpenWrt 替代认证软件 `glaclient`（守护进程 + LuCI 界面），实现多账号并发认证与带宽叠加，替代现网 Win11 虚拟机跑原客户端的方案。

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

### 1.2 已交付代码（在 `scripts/` 目录，全部可运行）

| 文件 | 作用 |
|---|---|
| `glaclient_reimpl.py` | ★ Python 参考实现：DES、请求构建、AuthSession 多会话引擎、virtual NIC 生成、CLI。**C 移植的对拍基准** |
| `des_data_codec.py` | `&data=` DES 编解码器，内置 NBS 官方测试向量自检 |
| `glaclient_ui.py` | tkinter 图形版（Windows 可用），多账号保存（accounts.json） |
| `keep_password_codec.py` | config.ini 记住密码解密 |
| `des_tables_check.py` | DES 8 表 FIPS 46 一致性验证 |

**验证状态**：DES 通过 NBS KAT（`8CA64DE9C1B123A7`）；mock 网关 5 账号×5 虚拟网卡并发 e2e 通过。**但从未接触真实网关**——这正是本阶段任务。

---

## 2. 现网环境（生产区 · 一律不动）

来源：https://blog.sweizh.top/post/lab-nat（实验室网络搭建记录）

| 设备 | IP | 角色 | Agent 权限 |
|---|---|---|---|
| Win11 虚拟机 | 10.10.94.22 | 冰川认证 + ClashVerge(7897) + CCproxy(1080) + 达芬奇项目库 | **禁止一切操作**（含抓包——金标准抓包在测试 Win 上做） |
| iStoreOS 虚拟机 | 10.10.94.40 | 团队网关 V2rayA 分流，全实验室依赖 | **禁止一切操作** |
| 小米 CR8806 | 10.10.94.30 | ImmortalWrt 无线发射（MT7621） | **禁止一切操作** |
| 飞牛 NAS 宿主机 | 10.10.94.31 | fnOS + OVS + 全部虚拟机 | 仅通过其虚拟机界面**新建**测试 VM，不动现有配置 |
| 校园网关 | 10.10.94.1:3080 | Portal 认证，单账号限速 ~100Mbps | 测试对象 |

**关键现网事实**：团队全部流量经代理从 10.10.94.22 的认证 IP 出去 = 网关按 IP 认证、不限制 IP 背后连接数的现成实证。全团队共享单账号 100Mbps 是本项目要解决的痛点。

---

## 3. 测试隔离区（用户新建，Agent 工作范围）

| 虚拟机 | 系统 | 网络接法 | 职责 |
|---|---|---|---|
| **Debian** ★ | Debian 12，装 TraeCode CLI | bridge 校园网，DHCP 拿 10.10.94.x | **Agent 大本营**：跑参考实现、SSH 指挥他机、抓包分析、阶段 3 macvlan 探测、阶段 4 编译 ipk |
| **Win 测试** | Win10 LTSC / Win11 IoT LTSC，装原版冰川客户端 | 同上 | 金标准机：抓原客户端真实登录流量做逐字节对照。平时可关机 |
| **OpenWrt**（阶段 4 才建） | OpenWrt 23.05.x x86_64 `generic-ext4-combined` | 同上 | ipk 安装载体，iperf3 叠加实测 |

**网络要点**：
- 三台 VM 网卡均出自飞牛 OVS bridge——macvlan 在 VM 内部虚拟网卡上建，OVS 只做 MAC 学习，无障碍。
- 未认证设备无外网。**Agent 的 API 流量走代理**：`HTTP_PROXY/HTTPS_PROXY=http://10.10.94.22:7897`，且必须 `NO_PROXY=10.10.94.1,10.0.0.0/8,localhost`。
- **铁律：认证请求绝不走代理**，必须直连 10.10.94.1:3080，否则测试作废且可能干扰生产认证。

---

## 4. 用户提供清单（收到后才开工）

```
[ ] Debian VM：IP + sudo 账号密码（Agent 所在机，本机）
[ ] Win 测试 VM：IP + SSH 管理员账号密码（pktmon 需管理员）
[ ] 测试校园网账号：工/学号 + 密码（用户本人的，禁用团队日常账号）
[ ] OpenWrt VM（阶段 4 前）：IP + root 密码
[ ] 两台 VM 均已拍快照（名字告知）
```

---

## 5. 分阶段执行计划

### 阶段 1：金标准抓包对照（风险≈零）
1. SSH 进 Win 测试 VM。
2. 起抓包（Win 自带，无需装软件）：
   ```powershell
   pktmon filter add gc -p 3080
   pktmon start --capture --pkt-size 0 -f C:\gc.etl
   # → 提示用户：在冰川客户端点一次"登录"（唯一人工步骤，约10秒）
   pktmon stop
   pktmon etl2pcapng C:\gc.etl -o C:\gc.pcapng   # Win11 新版为 pcapngfmt 子命令
   ```
   注意 `--pkt-size 0` 必加（默认 128 字节会截断 data=）。
3. scp 拉回 Debian，解析 GET 请求中 `time=` 与 `data=`。
4. 用 time 作 DES 密钥解密 data，与逆向明文结构逐字段比对；比对请求格式/headers/响应判定串。
5. 产出《金标准对照报告》：一致则逆向实锤；不一致则修正逆向实现后复测。
   备选方案：SSH 未就绪时，可请用户在飞牛宿主机 OVS 桥上 `tcpdump -i <br> host <WinIP> and port 3080 -w gc.pcap`（只读被动）。

### 阶段 2：单账号真实网关实测（风险=正常登录一次）
1. Debian 上直连（禁代理）跑 `glaclient_reimpl.py`：login → 数轮 keepalive → logoff。
2. 记录网关全部响应：成功串、错误码字典（密码错/重复登录/超时等）。
3. 产出协议验证结论。失败则对照阶段 1 抓包修正。

### 阶段 3：多账号/macvlan 探测（中风险，每步先报告待用户批准）
1. Debian 上 `ip link add link eth0 type macvlan`（或参考实现内置 virtual NIC）生成 2–4 个身份。
2. 逐步：同账号双身份 → 异账号双身份 → 4 身份，观察网关反应与限速行为。
3. 回答判决性问题：**限速按 IP 还是按账号？同端口多 MAC 是否触发风控？**
4. iperf3 多连接测各身份独立带宽 → 叠加是否成立的最终结论。
5. 任何异常（认证被拒/IP 被封迹象）立即停止并报告。

### 阶段 4：软件开发与打包
1. C 版 `glaclientd`（内置 DES 表，零依赖，<30KB）+ procd init + uci 配置 + nftables 按流分流（五元组哈希到 N 个认证出口，SNAT 各出口）。
2. **交叉验证铁律**：C 版与 Python 版对同一输入必须产生逐字节相同的密文与请求，mock 网关全流程回归后才上真机。
3. LuCI 管理页 `luci-app-glaclient`：账号管理、会话状态、各出口流量监控。
4. Debian 上拉 OpenWrt SDK 23.05（x86_64）编译 ipk → 装 OpenWrt 测试 VM → iperf3 实测叠加倍数。
5. 源码按开源结构整理（见第 7 节），GitHub Actions CI：tag → 双架构（x86_64 + mipsel/MT7621）→ usign 签名索引 → GitHub Releases。

### 阶段 5：生产切换方案书（用户拍板后执行）
新认证 VM/设备部署 → 逐步替换 Win11 认证角色 → Clash 链路平移 → 回滚预案。完成后 Win11 可卸冰川客户端与 CCproxy，仅留达芬奇库。

---

## 6. 风险红线（任何阶段适用）

1. 生产区四台设备（§2）零操作；唯一例外：飞牛界面新建测试 VM。
2. 认证流量永不走代理（§3 铁律）。
3. 多账号行为（阶段 3 起）每步先报告后执行；封号/违反校园网使用条款的风险归用户拍板。
4. 测试一律用用户提供的个人测试账号，绝不碰团队日常账号。
5. 真实账号、密码、抓包中的 PII 永不写入开源仓库；报告脱敏后提交。
6. 每个破坏性动作前确认测试 VM 快照存在。

---

## 7. 最终交付物清单

| 类别 | 内容 |
|---|---|
| 软件 | `glaclient` + `luci-app-glaclient` ipk（x86_64 + mipsel 双架构）、nftables 分流规则 |
| 开源仓库 | GPL-3.0；结构：`src/`（C 源码）、`luci/`、`Makefile`、`files/etc/uci-defaults`、`.github/workflows/build.yml`；README 中英双语，含风险声明 |
| 软件源 | GitHub Releases 当 opkg 源（`src/gz glaclient <release_url>` + usign 公钥）；README 附 ghproxy 加速与手动 ipk 兜底安装 |
| 报告 | 金标准对照报告、网关行为字典、多账号探测结论、iperf3 叠加实测数据、生产切换方案书、故障排查手册 |
| 过程资产 | 抓包样本+解析脚本、mock 网关回归套件 |

**明确不交付**：原软件源码复刻、单连接叠加（用户已砍掉）、网关服务端任何内容。

---

## 8. 随身文件清单（拷入 Debian VM 的内容）

```
cases/bcswkhd-audit/
├── HANDOFF-VM-AGENT.md      # 本文档
├── scripts/                 # 全部脚本（glaclient_reimpl.py 为对拍基准）
├── reports/README.md        # 完整逆向报告（协议细节的权威来源）
└── reports/vulnerability-report.md
```

Agent 开工自检：`python3 scripts/des_data_codec.py` 应输出 NBS KAT passed + roundtrip OK——不通过说明文件拷贝不完整，先解决再动。

---

## 9. Agent 行为约定

- 收到本文档 + §4 凭据清单后，先逐台连通性巡检（ping/SSH），再进阶段 1。
- 每阶段结束出报告，等用户确认再进下一阶段（阶段 2→3 之间必须停）。
- 长编译任务 nohup 后台跑，会话断了下轮回收。
- 遇协议不符/网关异常/权限不足三类问题：停止、记录、报告，不猜测强推。
