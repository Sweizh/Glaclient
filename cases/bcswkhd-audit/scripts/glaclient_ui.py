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
    - 登录 / 自动保活 / 登出（复刻原客户端状态机：
      连续 3 次无响应 → 'over %d times unreceive data,reauth now'）
    - 实时日志显示（线程安全）
    - 跨平台 MAC/IP/主机名采集

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

from glaclient_reimpl import OK_MAP, build_request, send_request
import keep_password_codec as pwcodec

ACCOUNTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "accounts.json")
DEFAULT_SERVER = "10.10.94.1"
MAX_FAIL = 3  # 原客户端保活失败重认证阈值


class AuthUI:
    def __init__(self, root):
        self.root = root
        root.title("冰川认证客户端（替代版）Glaclient Reimpl")
        root.geometry("780x560")
        root.minsize(700, 480)

        self.accounts = []           # [{name,username,password_enc,server,language}]
        self.current = None          # 当前在线账号凭据（运行时内存）
        self.stop_event = threading.Event()
        self.worker = None           # 认证/保活线程
        self.online = False
        self.log_queue = queue.Queue()

        self._build_widgets()
        self._load_accounts()
        self._refresh_list()
        self.root.after(100, self._poll_log_queue)
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.log(f"[*] 账号库: {ACCOUNTS_FILE}")
        self.log("[*] 协议: GET /cgi/client_check (DES-ECB, key=&time=) 端口 3080")

    # ------------------------------------------------------------------ UI
    def _build_widgets(self):
        # 顶部状态栏
        top = ttk.Frame(self.root, padding=(8, 6))
        top.pack(fill=tk.X)
        ttk.Label(top, text="状态:").pack(side=tk.LEFT)
        self.status_var = tk.StringVar(value="离线")
        self.status_lbl = ttk.Label(top, textvariable=self.status_var,
                                    foreground="#c62828", font=("", 10, "bold"))
        self.status_lbl.pack(side=tk.LEFT, padx=(4, 0))
        ttk.Label(top, text="当前账号:").pack(side=tk.LEFT, padx=(16, 0))
        self.cur_var = tk.StringVar(value="-")
        ttk.Label(top, textvariable=self.cur_var).pack(side=tk.LEFT)

        # 中部：左账号列表 + 右表单
        mid = ttk.Frame(self.root, padding=(8, 2))
        mid.pack(fill=tk.BOTH, expand=True)

        left = ttk.LabelFrame(mid, text=" 账号列表 ", padding=5)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 6))
        self.listbox = tk.Listbox(left, width=26, height=14, exportselection=False)
        self.listbox.pack(fill=tk.Y)
        self.listbox.bind("<<ListboxSelect>>", self._on_select)
        ttk.Button(left, text="＋ 新建账号", command=self._new_account
                   ).pack(fill=tk.X, pady=(6, 0))
        ttk.Button(left, text="✖ 删除账号", command=self._delete_account
                   ).pack(fill=tk.X, pady=(4, 0))

        right = ttk.LabelFrame(mid, text=" 账号信息 ", padding=8)
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
        ttk.Button(right, text="💾 保存账号", command=self._save_account
                   ).grid(row=6, column=1, sticky="w", padx=4, pady=(8, 2))
        right.columnconfigure(1, weight=1)

        # 操作区
        act = ttk.LabelFrame(self.root, text=" 认证操作 ", padding=8)
        act.pack(fill=tk.X, padx=8, pady=(4, 2))
        self.login_btn = ttk.Button(act, text="登录并保活", command=self._login)
        self.login_btn.pack(side=tk.LEFT)
        self.logout_btn = ttk.Button(act, text="登出", command=self._logout,
                                     state=tk.DISABLED)
        self.logout_btn.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(act, text="仅登录一次（不保活）",
                   command=lambda: self._login(keepalive=False)
                   ).pack(side=tk.LEFT, padx=(8, 0))

        # 日志区
        logf = ttk.LabelFrame(self.root, text=" 日志 ", padding=4)
        logf.pack(fill=tk.BOTH, expand=True, padx=8, pady=(2, 8))
        self.log_text = ScrolledText(logf, height=9, state=tk.DISABLED,
                                     font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _field(self, parent, row, label, default, show=None):
        """表单行：Label + Entry，返回 StringVar。"""
        var = tk.StringVar(value=default)
        ttk.Label(parent, text=label + ":").grid(
            row=row, column=0, sticky="e", padx=4, pady=3)
        e = ttk.Entry(parent, textvariable=var, show=show)
        e.grid(row=row, column=1, sticky="ew", padx=4, pady=3)
        if show:
            self.pwd_entry = e  # 供显示/隐藏切换
        return var

    def _toggle_pwd(self):
        self.pwd_entry.config(show="" if self.show_pwd.get() else "*")

    # ------------------------------------------------------------- 账号存储
    def _load_accounts(self):
        try:
            with open(ACCOUNTS_FILE, encoding="utf-8") as f:
                self.accounts = json.load(f)
        except (OSError, ValueError):
            self.accounts = []

    def _save_accounts(self):
        try:
            with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
                json.dump(self.accounts, f, ensure_ascii=False, indent=2)
        except OSError as e:
            messagebox.showerror("保存失败", str(e))

    def _refresh_list(self, select=None):
        self.listbox.delete(0, tk.END)
        for acc in self.accounts:
            self.listbox.insert(tk.END, acc.get("name", acc["username"]))
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
        except (AssertionError, ValueError):
            self.pwd_var.set("")
        self.server_var.set(acc.get("server", DEFAULT_SERVER))
        self.lang_var.set(acc.get("language", "1"))

    def _collect_form(self):
        return {
            "name": self.name_var.get().strip() or self.un_var.get().strip(),
            "username": self.un_var.get().strip(),
            "password": self.pwd_var.get(),
            "server": self.server_var.get().strip() or DEFAULT_SERVER,
            "language": self.lang_var.get(),
        }

    def _new_account(self):
        self.listbox.selection_clear(0, tk.END)
        self.name_var.set("")
        self.un_var.set("")
        self.pwd_var.set("")
        self.server_var.set(DEFAULT_SERVER)
        self.lang_var.set("1")
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
        }
        sel = self.listbox.curselection()
        idx = sel[0] if sel else len(self.accounts)
        if sel:
            self.accounts[sel[0]] = entry
        else:
            self.accounts.append(entry)
        self._save_accounts()
        self._refresh_list(select=idx)
        self.log(f"[+] 账号已保存: {entry['name']} ({cred['server']})")

    def _delete_account(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("提示", "请先在列表中选择账号")
            return
        acc = self.accounts[sel[0]]
        if messagebox.askyesno("删除账号", f"确定删除「{acc['name']}」？"):
            self.accounts.pop(sel[0])
            self._save_accounts()
            self._refresh_list()
            self.log(f"[-] 账号已删除: {acc['name']}")

    # ----------------------------------------------------------------- 认证
    def _do_method(self, cred, method, timeout=8):
        """在工作线程中执行一次协议请求（每次重新生成时间密钥）。"""
        req, t, data, pt = build_request(
            cred["server"], cred["username"], cred["password"],
            method, cred.get("language", "1"))
        resp = send_request(cred["server"], req, timeout=timeout)
        return OK_MAP[method] in resp, resp

    def _login(self, keepalive=True):
        cred = self._collect_form()
        if not (cred["username"] and cred["password"]):
            messagebox.showwarning("提示", "用户名和密码不能为空")
            return
        try:
            interval = max(3, int(self.interval_var.get()))
        except ValueError:
            interval = 20

        # 停掉旧线程
        self.stop_event.set()
        if self.worker and self.worker.is_alive():
            self.worker.join(timeout=3)
        self.stop_event = threading.Event()

        self.current = cred
        self.login_btn.config(state=tk.DISABLED)
        self.worker = threading.Thread(
            target=self._auth_worker, args=(dict(cred), interval, keepalive),
            daemon=True)
        self.worker.start()

    def _auth_worker(self, cred, interval, keepalive):
        self.log(f"[*] login -> {cred['server']}:3080 (un={cred['username']})")
        try:
            ok, resp = self._do_method(cred, "login")
        except OSError as e:
            ok, resp = False, f"network error: {e}"
        if not ok:
            self._set_status(False, cred)
            self.log(f"[!] login FAILED\n{resp.strip()[:400]}")
            return
        self._set_status(True, cred)
        self.log("[+] login OK — auth_ok")
        if keepalive:
            self._keepalive_worker(cred, interval)

    def _keepalive_worker(self, cred, interval):
        """可停止版保活循环（复刻 0x407310 客户端状态机）。"""
        fails, n = 0, 0
        while not self.stop_event.is_set():
            n += 1
            try:
                ok, resp = self._do_method(cred, "keepalive")
                if ok:
                    fails = 0
                    self.log(f"[{time.strftime('%H:%M:%S')}] keepalive #{n}: ok")
                else:
                    fails += 1
                    self.log(f"[!] keepalive #{n}: unexpected response")
            except OSError as e:
                fails += 1
                self.log(f"[!] keepalive #{n} network error: {e}")
            if fails >= MAX_FAIL:
                self.log(f"[!] over {MAX_FAIL} times unreceive data, reauth now")
                try:
                    ok, _ = self._do_method(cred, "login")
                    self.log(f"[{'+' if ok else '!'}] reauth "
                             f"{'OK' if ok else 'FAILED'}")
                    if ok:
                        fails = 0
                except OSError as e:
                    self.log(f"[!] reauth error: {e}")
            self.stop_event.wait(interval)
        self.log("[*] keepalive loop stopped")

    def _logout(self):
        cred = self.current
        if not cred:
            return
        self.stop_event.set()  # 先停保活循环
        self.logout_btn.config(state=tk.DISABLED)

        def do_logout():
            try:
                ok, resp = self._do_method(cred, "logoff")
                self.log(f"[{'+' if ok else '!'}] logoff "
                         f"{'OK — logoff_ok' if ok else 'FAILED: ' + resp.strip()[:200]}")
            except OSError as e:
                self.log(f"[!] logoff network error: {e}")
            self._set_status(False, None)

        threading.Thread(target=do_logout, daemon=True).start()

    # ------------------------------------------------------------ UI 线程安全
    def log(self, msg):
        self.log_queue.put(msg)

    def _poll_log_queue(self):
        lines = []
        while True:
            try:
                lines.append(self.log_queue.get_nowait())
            except queue.Empty:
                break
        if lines:
            self.log_text.config(state=tk.NORMAL)
            for l in lines:
                self.log_text.insert(tk.END, l + "\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        self.root.after(100, self._poll_log_queue)

    def _set_status(self, online, cred):
        self.root.after(0, self._apply_status, online, cred)

    def _apply_status(self, online, cred):
        self.online = online
        self.status_var.set("在线" if online else "离线")
        self.status_lbl.config(foreground="#2e7d32" if online else "#c62828")
        self.cur_var.set(cred["name"] if cred else "-")
        self.login_btn.config(state=tk.NORMAL)
        self.logout_btn.config(state=tk.NORMAL if online else tk.DISABLED)

    def _on_close(self):
        if self.online and self.current:
            if messagebox.askyesno("退出", "当前在线，退出前登出该账号？"):
                self.stop_event.set()
                try:
                    ok, _ = self._do_method(self.current, "logoff", timeout=3)
                    self.log(f"[{'+' if ok else '!'}] logoff on exit")
                except OSError:
                    pass
        self.stop_event.set()
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
