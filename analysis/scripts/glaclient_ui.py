#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
glaclient_ui.py — 冰川认证客户端（替代版）图形界面
================================================
基于逆向恢复的认证协议（glaclient_reimpl.py）的 tkinter GUI。
Python 标准库实现，Windows/macOS/Linux 全平台零依赖
（Windows 官方 Python 安装包自带 tkinter）。

功能：
    - 多账号管理（增/删/改/保存），密码用原客户端同款算法
      （mfc101f.dll 0x405020/0x405190，种子 0x522）加密存于 accounts.json
    - 虚拟网卡：自定义数量一键生成（随机 MAC + 顺序 IP），
      绑定到账号后认证明文使用该虚拟身份（ip|user|pwd|host|...|MAC|...）
      ——绕开原客户端"单网卡"限制
    - 多网卡多账户并发认证：每账号独立 AuthSession 线程，
      同时登录/保活/登出，会话面板实时显示各会话状态
    - 复刻原客户端状态机：连续 3 次无响应自动重认证
    - 实时日志（线程安全队列）

用法：
    python3 glaclient_ui.py          # Windows: 双击运行或 python glaclient_ui.py

协议（全部反汇编验证，见 ../reports/README.md）：
    GET /cgi/client_check?un=<用户名>&mymethod=<login|keepalive|logoff>
        &login_client=win32&language=<l>&time=<HH:MM:SS>&data=<DES密文hex>&debug=no&
    密钥 = time 值（DES-ECB）；明文 = ip|user|pwd|host|0|||MAC|11111111
"""
import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from glaclient_reimpl import (AuthSession, OK_MAP, build_request,
                              generate_virtual_nics, send_request,
                              VirtualNicManager)
import keep_password_codec as pwcodec

ACCOUNTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "accounts.json")
DEFAULT_SERVER = "10.10.94.1"
MAX_FAIL = 3  # 原客户端保活失败重认证阈值

STATE_TEXT = {
    "login":      ("在线", "#2e7d32"),
    "keepalive":  ("在线", "#2e7d32"),
    "reauth":     ("重连中", "#ef6c00"),
    "logoff":     ("离线", "#c62828"),
    "stopped":    ("离线", "#c62828"),
    "failed":     ("失败", "#c62828"),
}


class AuthUI:
    def __init__(self, root):
        self.root = root
        root.title("冰川认证客户端（替代版）Glaclient Reimpl — 多账号多虚拟网卡")
        root.geometry("860x720")
        root.minsize(780, 640)

        self.accounts = []           # [{name,username,password_enc,server,
                                     #   language,virtual_ip,virtual_mac,virtual_hostname}]
        self.sessions = {}           # username -> AuthSession（并发会话）
        self.log_queue = queue.Queue()
        self.vnic_mgr = None         # OS 级真实虚拟网卡管理器
        self.os_bound_ips = set()    # 已创建真实接口的 IP（会话 bind 用）

        self._build_widgets()
        self._load_accounts()
        self._refresh_list()
        self.root.after(100, self._poll_queue)
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.log(f"[*] 账号库: {ACCOUNTS_FILE}")
        self.log("[*] 协议: GET /cgi/client_check (DES-ECB, key=&time=) 端口 3080")
        self.log("[*] 多账号并发: 每账号独立线程 + 可选虚拟网卡身份")

    # ------------------------------------------------------------------ UI
    def _build_widgets(self):
        # 顶部状态栏
        top = ttk.Frame(self.root, padding=(8, 6))
        top.pack(fill=tk.X)
        ttk.Label(top, text="在线会话:").pack(side=tk.LEFT)
        self.status_var = tk.StringVar(value="0")
        self.status_lbl = ttk.Label(top, textvariable=self.status_var,
                                    foreground="#2e7d32", font=("", 10, "bold"))
        self.status_lbl.pack(side=tk.LEFT, padx=(4, 8))
        ttk.Label(top, text="/ 已配置账号:").pack(side=tk.LEFT)
        self.acc_var = tk.StringVar(value="0")
        ttk.Label(top, textvariable=self.acc_var).pack(side=tk.LEFT)

        # 中部：左账号列表 + 右表单
        mid = ttk.Frame(self.root, padding=(8, 2))
        mid.pack(fill=tk.BOTH, expand=True)

        left = ttk.LabelFrame(mid, text=" 账号列表 ", padding=5)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 6))
        self.listbox = tk.Listbox(left, width=24, height=13, exportselection=False)
        self.listbox.pack(fill=tk.Y)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)
        ttk.Button(left, text="＋ 新建账号", command=self._new_account
                   ).pack(fill=tk.X, pady=(6, 0))
        ttk.Button(left, text="✖ 删除账号", command=self._delete_account
                   ).pack(fill=tk.X, pady=(4, 0))

        right = ttk.LabelFrame(mid, text=" 账号信息（虚拟网卡留空 = 用真实网卡）",
                               padding=8)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.name_var = self._field(right, 0, "备注名称", "宿舍账号")
        self.un_var = self._field(right, 1, "用户名（学号/工号）", "2202160228")
        self.pwd_var = self._field(right, 2, "密码", "169332", show="*")
        # 显示密码开关（放密码框右侧）
        self.show_pwd = tk.BooleanVar(value=False)
        ttk.Checkbutton(right, text="显示", variable=self.show_pwd,
                        command=self._toggle_pwd).grid(
            row=2, column=2, sticky="w", padx=2)
        self.server_var = self._field(right, 3, "认证服务器 IP", DEFAULT_SERVER)
        self.lang_var = tk.StringVar(value="1")
        ttk.Label(right, text="language 参数:").grid(
            row=4, column=0, sticky="e", padx=4, pady=3)
        lang_box = ttk.Combobox(right, textvariable=self.lang_var,
                                values=("1", "2", "0"), width=6, state="readonly")
        lang_box.grid(row=4, column=1, sticky="w", padx=4, pady=3)
        self.interval_var = self._field(right, 5, "保活间隔（秒）", "20")
        # 虚拟网卡三字段（绑定到账号）
        ttk.Separator(right, orient=tk.HORIZONTAL).grid(
            row=6, column=0, columnspan=3, sticky="ew", pady=(6, 2))
        ttk.Label(right, text="— 虚拟网卡（本账号绑定的认证身份）—",
                  foreground="#1565c0").grid(
            row=7, column=0, columnspan=3, sticky="w", pady=(2, 3))
        self.vip_var = self._field(right, 8, "虚拟 IP", "")
        self.vmac_var = self._field(right, 9, "虚拟 MAC", "")
        self.vhost_var = self._field(right, 10, "虚拟主机名", "")
        ttk.Button(right, text="🎲 随机 MAC", command=self._rand_mac
                   ).grid(row=9, column=2, sticky="w", padx=2)
        ttk.Button(right, text="💾 保存账号", command=self._save_account
                   ).grid(row=11, column=1, sticky="w", padx=4, pady=(8, 2))
        right.columnconfigure(1, weight=1)

        # 虚拟网卡批量生成区
        vn = ttk.LabelFrame(
            self.root, text=" 虚拟网卡批量生成（自动分配给未绑定的账号） ",
            padding=8)
        vn.pack(fill=tk.X, padx=8, pady=(4, 2))
        ttk.Label(vn, text="数量:").pack(side=tk.LEFT)
        self.vnic_count_var = tk.StringVar(value="3")
        ttk.Spinbox(vn, from_=1, to=64, width=4,
                    textvariable=self.vnic_count_var).pack(side=tk.LEFT, padx=(2, 10))
        ttk.Label(vn, text="IP 前缀:").pack(side=tk.LEFT)
        self.vnic_prefix_var = tk.StringVar(value="10.10.94")
        ttk.Entry(vn, width=12, textvariable=self.vnic_prefix_var
                  ).pack(side=tk.LEFT, padx=(2, 10))
        ttk.Label(vn, text="起始主机号:").pack(side=tk.LEFT)
        self.vnic_start_var = tk.StringVar(value="100")
        ttk.Entry(vn, width=6, textvariable=self.vnic_start_var
                  ).pack(side=tk.LEFT, padx=(2, 10))
        ttk.Button(vn, text="⚡ 生成并分配（明文模式）",
                   command=self._generate_vnics).pack(side=tk.LEFT)
        ttk.Button(vn, text="🔌 创建 OS 真实虚拟网卡（插卡模式）",
                   command=self._create_os_vnics).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Label(vn, text="明文=仅声明身份；OS=数据包源 IP 即虚拟 IP"
                          "（Linux: macvlan 独立 MAC / Win: IP 别名），需管理员",
                  foreground="#888").pack(side=tk.LEFT, padx=(10, 0))

        # 操作区
        act = ttk.LabelFrame(self.root, text=" 认证操作 ", padding=8)
        act.pack(fill=tk.X, padx=8, pady=(4, 2))
        self.login_btn = ttk.Button(act, text="▶ 登录选中账号", command=self._login)
        self.login_btn.pack(side=tk.LEFT)
        ttk.Button(act, text="▶▶ 全部登录（多账号并发）",
                   command=self._login_all).pack(side=tk.LEFT, padx=(8, 0))
        self.logout_btn = ttk.Button(act, text="■ 登出选中", command=self._logout)
        self.logout_btn.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(act, text="■■ 全部登出", command=self._logout_all
                   ).pack(side=tk.LEFT, padx=(8, 0))

        # 会话面板（多会话实时状态）
        sf = ttk.LabelFrame(self.root, text=" 在线会话（多网卡多账户） ", padding=4)
        sf.pack(fill=tk.BOTH, expand=True, padx=8, pady=(2, 2))
        cols = ("name", "un", "nic", "state", "last")
        self.tree = ttk.Treeview(sf, columns=cols, show="headings", height=5)
        for cid, txt, w, a in (
                ("name", "账号", 120, "w"), ("un", "用户名", 110, "w"),
                ("nic", "网卡（IP / MAC）", 250, "w"),
                ("state", "状态", 70, "center"), ("last", "最后活动", 90, "center")):
            self.tree.heading(cid, text=txt)
            self.tree.column(cid, width=w, anchor=a)
        self.tree.column("name", stretch=True)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.tag_configure("on", foreground="#2e7d32")
        self.tree.tag_configure("fail", foreground="#c62828")
        self.tree.tag_configure("warn", foreground="#ef6c00")

        # 日志区
        logf = ttk.LabelFrame(self.root, text=" 日志 ", padding=4)
        logf.pack(fill=tk.BOTH, expand=True, padx=8, pady=(2, 8))
        self.log_text = ScrolledText(logf, height=7, state=tk.DISABLED,
                                     font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _field(self, parent, row, label, default, show=None):
        """表单行：Label + Entry，返回 StringVar。"""
        var = tk.StringVar(value=default)
        ttk.Label(parent, text=label + ":").grid(
            row=row, column=0, sticky="e", padx=4, pady=2)
        e = ttk.Entry(parent, textvariable=var, show=show)
        e.grid(row=row, column=1, sticky="ew", padx=4, pady=2)
        if show:
            self.pwd_entry = e  # 供显示/隐藏切换
        return var

    def _toggle_pwd(self):
        self.pwd_entry.config(show="" if self.show_pwd.get() else "*")

    def _rand_mac(self):
        """表单里随机一个 02 开头的虚拟 MAC。"""
        import random
        mac = "02" + "".join("%02X" % random.randrange(256) for _ in range(5))
        self.vmac_var.set(mac)

    # ------------------------------------------------------------- 账号存储
    def _load_accounts(self):
        try:
            with open(ACCOUNTS_FILE, encoding="utf-8") as f:
                self.accounts = json.load(f)
        except (OSError, ValueError):
            self.accounts = []
        self.acc_var.set(str(len(self.accounts)))

    def _save_accounts(self):
        try:
            with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.accounts, f, ensure_ascii=False, indent=2)
        except OSError as e:
            messagebox.showerror("保存失败", str(e))

    def _refresh_list(self, select=None):
        self.listbox.delete(0, tk.END)
        for acc in self.accounts:
            tag = acc.get("name", acc["username"])
            vnic = " [V]" if (acc.get("virtual_ip") or acc.get("virtual_mac")) else ""
            self.listbox.insert(tk.END, tag + vnic)
        self.acc_var.set(str(len(self.accounts)))
        if select is not None and 0 <= select < len(self.accounts):
            self.listbox.selection_set(select)
            self.listbox.see(select)

    def _on_select(self, _event=None):
        sel = self.listbox.curselection()
        if not sel or sel[0] >= len(self.accounts):
            return
        acc = self.accounts[sel[0]]
        self.name_var.set(acc.get("name", ""))
        self.un_var.set(acc.get("username", ""))
        try:
            self.pwd_var.set(pwcodec.decode(acc["password_enc"]))
        except (AssertionError, ValueError, KeyError):
            self.pwd_var.set("")
        self.server_var.set(acc.get("server", DEFAULT_SERVER))
        self.lang_var.set(acc.get("language", "1"))
        self.vip_var.set(acc.get("virtual_ip", ""))
        self.vmac_var.set(acc.get("virtual_mac", ""))
        self.vhost_var.set(acc.get("virtual_hostname", ""))

    def _collect_form(self):
        return {
            "name": self.name_var.get().strip() or self.un_var.get().strip(),
            "username": self.un_var.get().strip(),
            "password": self.pwd_var.get(),
            "server": self.server_var.get().strip() or DEFAULT_SERVER,
            "language": self.lang_var.get(),
            "ip": self.vip_var.get().strip() or None,
            "mac": self.vmac_var.get().strip() or None,
            "hostname": self.vhost_var.get().strip() or None,
        }

    def _new_account(self):
        self.listbox.selection_clear(0, tk.END)
        self.name_var.set("")
        self.un_var.set("")
        self.pwd_var.set("")
        self.server_var.set(DEFAULT_SERVER)
        self.lang_var.set("1")
        self.vip_var.set("")
        self.vmac_var.set("")
        self.vhost_var.set("")
        self.log("[*] 新账号：填写后点「保存账号」")

    def _save_account(self):
        cred = self._collect_form()
        if not cred["username"]:
            messagebox.showwarning("提示", "用户名不能为空")
            return
        entry = {
            "name": cred["name"],
            "username": cred["username"],
            # 原客户端 [KeepPassword] 同款可逆加密（逆向恢复，见报告 VULN-03）
            "password_enc": pwcodec.encode(cred["password"]),
            "server": cred["server"],
            "language": cred["language"],
            "virtual_ip": cred["ip"] or "",
            "virtual_mac": cred["mac"] or "",
            "virtual_hostname": cred["hostname"] or "",
        }
        sel = self.listbox.curselection()
        idx = sel[0] if sel else len(self.accounts)
        if sel:
            self.accounts[sel[0]] = entry
        else:
            self.accounts.append(entry)
        self._save_accounts()
        self._refresh_list(select=idx)
        nic = f"vNIC {cred['ip']}/{cred['mac']}" if (cred["ip"] or cred["mac"]) \
              else "real nic"
        self.log(f"[+] 账号已保存: {entry['name']} ({cred['server']}, {nic})")

    def _delete_account(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("提示", "请先在列表中选择账号")
            return
        acc = self.accounts[sel[0]]
        if messagebox.askyesno("删除账号", f"确定删除「{acc['name']}」？"):
            # 若该账号在线，先停掉会话
            un = acc.get("username")
            if un in self.sessions:
                self.sessions.pop(un).stop(logoff=True)
                self.tree.delete(un)
            self.accounts.pop(sel[0])
            self._save_accounts()
            self._refresh_list()
            self.log(f"[-] 账号已删除: {acc['name']}")

    # --------------------------------------------------------- 虚拟网卡生成
    def _vnic_params(self):
        try:
            count = max(1, int(self.vnic_count_var.get()))
            start = int(self.vnic_start_var.get())
        except ValueError:
            messagebox.showwarning("提示", "数量/起始主机号必须是整数")
            return None
        prefix = self.vnic_prefix_var.get().strip() or "10.10.94"
        return count, prefix, start

    def _generate_vnics(self):
        """明文模式：生成虚拟网卡并分配给未绑定的账号（协议研究用）。"""
        params = self._vnic_params()
        if not params:
            return
        count, prefix, start = params
        nics = generate_virtual_nics(count, prefix, start)
        assigned = 0
        j = 0
        for acc in self.accounts:
            if not (acc.get("virtual_ip") or acc.get("virtual_mac")):
                if j < len(nics):
                    acc["virtual_ip"] = nics[j]["ip"]
                    acc["virtual_mac"] = nics[j]["mac"]
                    acc["virtual_hostname"] = nics[j]["hostname"]
                    j += 1
                    assigned += 1
        self._save_accounts()
        self._refresh_list()
        for n in nics:
            self.log(f"[+] vNIC {n['ip']}  {n['mac']}  {n['hostname']}")
        self.log(f"[+] 已生成 {count} 个虚拟网卡（{prefix}.{start} 起），"
                 f"已分配 {assigned} 个账号；还可在右侧表单为单账号手工填写")
        if assigned < len(nics):
            self.log(f"[*] 提示：{len(nics) - assigned} 个虚拟网卡未分配"
                     f"（所有账号均已绑定）；新建账号后可再分配")

    def _create_os_vnics(self):
        """插卡模式：OS 层创建真实虚拟网卡（数据包源 IP = 虚拟 IP）。

        Linux: macvlan（独立接口独立 MAC，等效插实体卡）
        Windows: 物理网卡 IP 别名（网关见独立 ARP 条目）
        需管理员/root；创建后绑定会话自动从虚拟 IP 发包，退出时删除。
        """
        params = self._vnic_params()
        if not params:
            return
        count, prefix, start = params
        # 若已有 OS 虚拟网卡先删除（重复点击/调整数量）
        if self.vnic_mgr:
            self.vnic_mgr.destroy()
            self.os_bound_ips.clear()
            self.log("[*] 已删除旧 OS 虚拟网卡")
        self.vnic_mgr = VirtualNicManager()
        if not self.vnic_mgr.has_privilege():
            self.log(f"[!] 无{'管理员' if self.vnic_mgr.os_name == 'windows' else 'root'}权限："
                     f"请以{'管理员身份重新运行（Windows 右键→以管理员身份运行）' if self.vnic_mgr.os_name == 'windows' else 'sudo 运行'}，"
                     f"或改用「明文模式」")
            messagebox.showwarning(
                "需要权限",
                f"创建 OS 级真实虚拟网卡需要"
                f"{'管理员权限（请右键以管理员身份运行本程序）' if self.vnic_mgr.os_name == 'windows' else 'root 权限（sudo 运行）'}。\n\n"
                f"明文模式无需权限，但数据包源 IP 仍是物理网卡主 IP。")
            self.vnic_mgr = None
            return
        try:
            nics = self.vnic_mgr.create(count, prefix, start)
        except (PermissionError, RuntimeError) as e:
            self.log(f"[!] OS 虚拟网卡创建失败: {e}")
            messagebox.showerror("创建失败", str(e))
            self.vnic_mgr = None
            return
        # 分配给未绑定账号（同明文模式逻辑）
        j, assigned = 0, 0
        for acc in self.accounts:
            if not (acc.get("virtual_ip") or acc.get("virtual_mac")):
                if j < len(nics):
                    acc["virtual_ip"] = nics[j]["ip"]
                    acc["virtual_mac"] = nics[j]["mac"]
                    acc["virtual_hostname"] = nics[j]["hostname"]
                    j += 1
                    assigned += 1
        self._save_accounts()
        self._refresh_list()
        for n in nics:
            self.os_bound_ips.add(n["ip"])
            kind = ("macvlan" if n["platform"] == "linux" else "IP 别名")
            self.log(f"[+] OS vNIC [{n['name']}] @{n['iface']} {n['ip']} "
                     f"mac={n['mac']} ({kind})")
        self.log(f"[+] 已创建 {count} 个 OS 级真实虚拟网卡并分配 {assigned} 个账号；"
                 f"登录后数据包将以各虚拟 IP 为源地址发往网关")
        self.log("[*] 提示：退出程序时将自动删除这些虚拟网卡")

    # --------------------------------------------------------- 并发认证会话
    def _interval(self):
        try:
            return max(3, int(self.interval_var.get()))
        except ValueError:
            return 20

    def _make_session(self, cred):
        un = cred["username"]
        # 同一账号重启：先停旧会话
        if un in self.sessions:
            self.sessions.pop(un).stop(logoff=True)

        def on_state(state, ok, _un=un):
            # 工作线程里调用 -> 入队，UI 线程消费
            self.log_queue.put(("_state", _un, state, ok))

        s = AuthSession(cred["server"], un, cred["password"],
                        cred.get("language", "1"),
                        ip=cred.get("ip"), mac=cred.get("mac"),
                        hostname=cred.get("hostname"),
                        interval=self._interval(), max_fail=MAX_FAIL,
                        on_log=self.log, on_state=on_state,
                        bind_ip=(cred.get("ip") if cred.get("ip")
                                 in self.os_bound_ips else None))
        self.sessions[un] = s
        # 会话表行（iid = username）
        bind = cred.get("ip") in self.os_bound_ips
        if bind:
            nic = f"OS-vnic {cred.get('ip')} (src IP)"
        elif cred.get("ip") or cred.get("mac"):
            nic = f"{cred.get('ip') or '-'}/{cred.get('mac') or '-'} (明文)"
        else:
            nic = "真实网卡"
        if self.tree.exists(un):
            self.tree.delete(un)
        self.tree.insert("", tk.END, iid=un,
                         values=(cred["name"], un, nic, "登录中…", "-"))
        return s

    def _login(self):
        cred = self._collect_form()
        if not (cred["username"] and cred["password"]):
            messagebox.showwarning("提示", "用户名和密码不能为空")
            return
        s = self._make_session(cred)
        s.start()

    def _login_all(self):
        """所有账号并发登录（多账号多虚拟网卡同时认证）。"""
        if not self.accounts:
            messagebox.showinfo("提示", "账号库为空，请先保存账号")
            return
        n = 0
        for acc in self.accounts:
            un = acc.get("username")
            if not un:
                continue
            try:
                pwd = pwcodec.decode(acc["password_enc"])
            except (AssertionError, ValueError, KeyError):
                self.log(f"[!] 账号 {un} 密码解码失败，跳过")
                continue
            cred = {
                "name": acc.get("name", un), "username": un, "password": pwd,
                "server": acc.get("server", DEFAULT_SERVER),
                "language": acc.get("language", "1"),
                "ip": acc.get("virtual_ip") or None,
                "mac": acc.get("virtual_mac") or None,
                "hostname": acc.get("virtual_hostname") or None,
            }
            s = self._make_session(cred)
            s.start()
            n += 1
        self.log(f"[*] 已发起 {n} 个并发认证会话")

    def _logout(self):
        cred = self._collect_form()
        un = cred["username"]
        s = self.sessions.get(un)
        if not s:
            messagebox.showinfo("提示", f"账号 {un or '(空)'} 无在线会话")
            return

        def do():
            s.stop(logoff=True)
            self.root.after(0, self._remove_session_row, un)

        threading.Thread(target=do, daemon=True).start()

    def _logout_all(self):
        for un, s in list(self.sessions.items()):
            def do(_s=s, _un=un):
                _s.stop(logoff=True)
                self.root.after(0, self._remove_session_row, _un)
            threading.Thread(target=do, daemon=True).start()
        self.log("[*] 正在登出全部会话…")

    def _remove_session_row(self, un):
        if un in self.sessions:
            self.sessions.pop(un)
        if self.tree.exists(un):
            self.tree.delete(un)
        self._update_session_count()

    def _update_session_count(self):
        n = sum(1 for s in self.sessions.values() if s.online)
        self.status_var.set(str(n))
        self.status_lbl.config(foreground="#2e7d32" if n else "#c62828")

    # ------------------------------------------------------------ UI 线程安全
    def log(self, msg):
        self.log_queue.put(msg)

    def _poll_queue(self):
        logs, states = [], []
        while True:
            try:
                item = self.log_queue.get_nowait()
            except queue.Empty:
                break
            if isinstance(item, tuple) and item[0] == "_state":
                states.append(item)
            else:
                logs.append(item)
        if logs:
            self.log_text.config(state=tk.NORMAL)
            for l in logs:
                self.log_text.insert(tk.END, l + "\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        for _tag, un, state, ok in states:
            self._apply_state(un, state, ok)
        self.root.after(100, self._poll_queue)

    def _apply_state(self, un, state, ok):
        """UI 线程内更新会话表行。"""
        if not self.tree.exists(un):
            return
        s = self.sessions.get(un)
        values = list(self.tree.item(un, "values"))
        if state in ("login", "reauth"):
            values[3] = STATE_TEXT[state][0] if ok else "失败"
            tag = "on" if ok else "fail"
        elif state == "keepalive":
            values[3] = "在线" if ok else "保活失败"
            tag = "on" if ok else "warn"
            if ok:
                values[4] = time.strftime("%H:%M:%S")
        else:  # stopped / logoff
            values[3] = "离线"
            tag = "fail"
        self.tree.item(un, values=values, tags=(tag,))
        self._update_session_count()

    def _on_close(self):
        if any(s.online for s in self.sessions.values()):
            if not messagebox.askyesno(
                    "退出", "仍有在线会话，退出前登出全部账号？\n"
                    "（选「否」将直接退出，会话可能在超时后掉线）"):
                self.root.destroy()
                return
        # 逐个登出（快速关闭：join 超时后仍销毁窗口）
        for s in list(self.sessions.values()):
            s.stop(logoff=True, timeout=2)
        # 删除本次创建的 OS 级虚拟网卡
        if self.vnic_mgr:
            try:
                self.vnic_mgr.destroy()
            except Exception:
                pass
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista")  # Windows 原生观感
    except tk.TclError:
        pass
    AuthUI(root)
    root.mainloop()


if __name__ == "__main__":
    sys.exit(main())
