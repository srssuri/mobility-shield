#!/usr/bin/env python3
"""Mobility Shield GUI (tkinter)"""
import os, sys, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from mobility_shield import (load_config, save_config, scan_path, scan_persistence,
                             scan_processes, scan_network, scan_hosts, scan_browsers,
                             scan_ads, save_report, quarantine_file, APP_DIR, QUARANTINE_DIR,
                             REPORTS_DIR, quick_scan_targets)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Mobility Shield")
        self.geometry("960x680")
        # window icon
        try:
            ico = os.path.join(os.path.dirname(os.path.abspath(__file__)), "png", "favicon.ico")
            if not os.path.exists(ico):
                ico = os.path.join(os.path.dirname(os.path.abspath(__file__)), "favicon.ico")
            if os.path.exists(ico):
                self.iconbitmap(ico)
        except Exception:
            pass
        self.minsize(820, 580)
        self.cfg = load_config()
        self.cancel = threading.Event()
        self.results = []
        self.extra = {}
        self._build()
        self._apply_style()

    def _apply_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TButton", padding=6)

    def _build(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="Mobility Shield", font=("Segoe UI", 16, "bold")).pack(side="left")
        ttk.Label(top, text="Lightweight on-demand scanner", foreground="#666").pack(side="left", padx=10)

        # Profile row
        prow = ttk.Frame(self, padding=(10, 0, 10, 5))
        prow.pack(fill="x")
        ttk.Label(prow, text="Profile:").pack(side="left")
        self.profile_var = tk.StringVar(value="Custom")
        ttk.Combobox(prow, textvariable=self.profile_var, values=["Custom", "Quick", "Full"],
                     state="readonly", width=12).pack(side="left", padx=6)
        ttk.Button(prow, text="Quick scan", command=lambda: self.run_profile("quick")).pack(side="left", padx=2)
        ttk.Button(prow, text="Full scan", command=lambda: self.run_profile("full")).pack(side="left", padx=2)

        # Target row
        row = ttk.Frame(self, padding=(10, 0, 10, 5))
        row.pack(fill="x")
        ttk.Label(row, text="Target:").pack(side="left")
        self.target_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.target_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(row, text="Browse file", command=self.browse_file).pack(side="left", padx=2)
        ttk.Button(row, text="Browse folder", command=self.browse_folder).pack(side="left", padx=2)

        # Options row
        opt = ttk.Frame(self, padding=(10, 0, 10, 5))
        opt.pack(fill="x")
        self.vt_var = tk.BooleanVar(value=bool(self.cfg.get("vt_api_key")))
        self.persist_var = tk.BooleanVar(value=True)
        self.procs_var = tk.BooleanVar(value=True)
        self.network_var = tk.BooleanVar(value=True)
        self.browsers_var = tk.BooleanVar(value=True)
        self.hosts_var = tk.BooleanVar(value=True)
        self.ads_var = tk.BooleanVar(value=False)
        self.quar_var = tk.BooleanVar(value=False)
        for txt, var in [("VirusTotal", self.vt_var), ("Persistence", self.persist_var),
                         ("Processes", self.procs_var), ("Network", self.network_var),
                         ("Browsers", self.browsers_var), ("Hosts/DNS", self.hosts_var),
                         ("ADS", self.ads_var), ("Auto-quarantine", self.quar_var)]:
            ttk.Checkbutton(opt, text=txt, variable=var).pack(side="left", padx=3)
        ttk.Button(opt, text="VT API key", command=self.set_vt_key).pack(side="right", padx=4)

        # Buttons
        btns = ttk.Frame(self, padding=(10, 0, 10, 5))
        btns.pack(fill="x")
        self.scan_btn = ttk.Button(btns, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=2)
        self.cancel_btn = ttk.Button(btns, text="Cancel", command=self.cancel_scan, state="disabled")
        self.cancel_btn.pack(side="left", padx=2)
        ttk.Button(btns, text="Open reports", command=self.open_reports).pack(side="left", padx=2)
        ttk.Button(btns, text="Open quarantine", command=self.open_quarantine).pack(side="left", padx=2)
        ttk.Button(btns, text="About", command=self.about).pack(side="right", padx=2)

        # Progress
        prog = ttk.Frame(self, padding=(10, 0, 10, 5))
        prog.pack(fill="x")
        self.progress = ttk.Progressbar(prog, mode="determinate")
        self.progress.pack(fill="x")
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(prog, textvariable=self.status_var, foreground="#666").pack(anchor="w", pady=2)

        # Notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=5)
        # Files
        ftab = ttk.Frame(nb); nb.add(ftab, text="File findings")
        cols = ("verdict", "path", "reasons")
        self.tree = ttk.Treeview(ftab, columns=cols, show="headings")
        self.tree.heading("verdict", text="Verdict"); self.tree.heading("path", text="Path")
        self.tree.heading("reasons", text="Reasons")
        self.tree.column("verdict", width=110); self.tree.column("path", width=420); self.tree.column("reasons", width=320)
        vsb = ttk.Scrollbar(ftab, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True); vsb.pack(side="right", fill="y")
        selbar = ttk.Frame(ftab); selbar.pack(fill="x", pady=4)
        ttk.Button(selbar, text="Quarantine selected", command=self.quarantine_selected).pack(side="left", padx=2)
        ttk.Button(selbar, text="Copy path", command=self.copy_path).pack(side="left", padx=2)

        # Persistence
        ptab = ttk.Frame(nb); nb.add(ptab, text="Persistence")
        self.persist_text = scrolledtext.ScrolledText(ptab, wrap="word", font=("Consolas", 9))
        self.persist_text.pack(fill="both", expand=True)
        # Processes
        prtab = ttk.Frame(nb); nb.add(prtab, text="Processes")
        self.proc_text = scrolledtext.ScrolledText(prtab, wrap="word", font=("Consolas", 9))
        self.proc_text.pack(fill="both", expand=True)
        # Network
        ntab = ttk.Frame(nb); nb.add(ntab, text="Network")
        self.net_text = scrolledtext.ScrolledText(ntab, wrap="word", font=("Consolas", 9))
        self.net_text.pack(fill="both", expand=True)
        # Browsers
        btab = ttk.Frame(nb); nb.add(btab, text="Browsers")
        self.browser_text = scrolledtext.ScrolledText(btab, wrap="word", font=("Consolas", 9))
        self.browser_text.pack(fill="both", expand=True)
        # Hosts
        htab = ttk.Frame(nb); nb.add(htab, text="Hosts")
        self.hosts_text = scrolledtext.ScrolledText(htab, wrap="word", font=("Consolas", 9))
        self.hosts_text.pack(fill="both", expand=True)
        # ADS
        atab = ttk.Frame(nb); nb.add(atab, text="ADS")
        self.ads_text = scrolledtext.ScrolledText(atab, wrap="word", font=("Consolas", 9))
        self.ads_text.pack(fill="both", expand=True)
        # Log
        ltab = ttk.Frame(nb); nb.add(ltab, text="Log")
        self.log_text = scrolledtext.ScrolledText(ltab, wrap="word", font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True)

    def log(self, msg):
        self.log_text.insert("end", msg + "\n"); self.log_text.see("end")

    def browse_file(self):
        f = filedialog.askopenfilename()
        if f: self.target_var.set(f)

    def browse_folder(self):
        d = filedialog.askdirectory()
        if d: self.target_var.set(d)

    def set_vt_key(self):
        key = tk.simpledialog.askstring("VirusTotal API key", "Paste your free VT API key (or leave empty):",
                                       initialvalue=self.cfg.get("vt_api_key", ""))
        if key is not None:
            self.cfg["vt_api_key"] = key.strip()
            save_config(self.cfg)
            self.vt_var.set(bool(self.cfg.get("vt_api_key")))
            messagebox.showinfo("Saved", "API key saved.")

    def open_reports(self):
        try: os.startfile(str(REPORTS_DIR))
        except Exception: pass

    def open_quarantine(self):
        try: os.startfile(str(QUARANTINE_DIR))
        except Exception: pass

    def about(self):
        win = tk.Toplevel(self)
        win.title("About Mobility Shield")
        win.geometry("420x320")
        win.resizable(False, False)
        try:
            ico = os.path.join(os.path.dirname(os.path.abspath(__file__)), "png", "favicon.ico")
            if os.path.exists(ico):
                win.iconbitmap(ico)
        except Exception:
            pass
        ttk.Label(win, text="Mobility Shield", font=("Segoe UI", 18, "bold")).pack(pady=(20, 4))
        ttk.Label(win, text="Lightweight on-demand security scanner", foreground="#666").pack()
        ttk.Label(win, text="Part of the Mobility-os project", foreground="#666").pack(pady=(0, 12))
        info = ("Version: 1.0\n"
                "Engine: Python 3.12\n"
                "Modules: heuristics, VirusTotal, persistence,\n"
                "         processes, network, browsers, hosts, ADS\n\n"
                "Complements (does not replace) Windows Defender.")
        ttk.Label(win, text=info, justify="center").pack()
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=16)

    def cancel_scan(self):
        self.cancel.set()

    def run_profile(self, profile):
        if profile == "quick":
            targets = quick_scan_targets()
            self.target_var.set(targets[0] if targets else "")
        else:
            self.target_var.set(str(__import__("pathlib").Path.home()))
        self.profile_var.set(profile.capitalize())
        # enable all modules for full
        if profile == "full":
            for v in (self.persist_var, self.procs_var, self.network_var, self.browsers_var, self.hosts_var):
                v.set(True)
        self.start_scan()

    def start_scan(self):
        target = self.target_var.get().strip()
        if not target or not os.path.exists(target):
            # allow quick profile with multiple targets handled in thread
            if self.profile_var.get() != "Quick":
                messagebox.showerror("Error", "Please select a valid file or folder.")
                return
        self.cancel.clear()
        self.results = []; self.extra = {}
        for r in self.tree.get_children(): self.tree.delete(r)
        for w in (self.persist_text, self.proc_text, self.net_text, self.browser_text, self.hosts_text, self.ads_text, self.log_text):
            w.delete("1.0", "end")
        self.scan_btn.config(state="disabled"); self.cancel_btn.config(state="normal")
        self.progress["value"] = 0
        threading.Thread(target=self._run_scan, args=(target,), daemon=True).start()

    def _run_scan(self, target):
        cfg = dict(self.cfg)
        cfg["vt_api_key"] = cfg.get("vt_api_key", "") if self.vt_var.get() else ""
        try:
            profile = self.profile_var.get()
            if profile == "Quick":
                targets = quick_scan_targets()
            else:
                targets = [target]
            all_results = []
            for t in targets:
                def progress(i, total, path):
                    if self.cancel.is_set(): return
                    self.after(0, lambda i=i, total=total, path=path: self._progress(i, total, path))
                r = scan_path(t, cfg, progress_cb=progress, cancel_flag=self.cancel)
                all_results.extend(r)
            self.results = all_results
            persist = scan_persistence() if self.persist_var.get() else []
            procs = scan_processes() if self.procs_var.get() else []
            network = scan_network() if self.network_var.get() else []
            browsers = scan_browsers() if self.browsers_var.get() else []
            hosts = scan_hosts() if self.hosts_var.get() else []
            ads = []
            if self.ads_var.get():
                for t in targets:
                    ads.extend(scan_ads(t))
            self.extra = {"network": network, "browsers": browsers, "hosts": hosts, "ads": ads}
            if self.quar_var.get():
                for r in all_results:
                    if r.get("verdict") == "malicious":
                        try:
                            q = quarantine_file(r["path"])
                            self.after(0, lambda p=r["path"], q=q: self.log(f"Quarantined: {p} -> {q}"))
                        except Exception as e:
                            self.after(0, lambda e=e: self.log(f"Quarantine failed: {e}"))
            jpath, tpath = save_report(all_results, persist, procs, " + ".join(targets), extra=self.extra)
            self.after(0, lambda: self._finish(all_results, persist, procs, network, browsers, hosts, ads, tpath))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.after(0, self._reset_buttons)

    def _progress(self, i, total, path):
        if total: self.progress["value"] = (i / total) * 100
        self.status_var.set(f"[{i}/{total}] {path}")
        self.log(f"[{i}/{total}] {path}")

    def _finish(self, results, persist, procs, network, browsers, hosts, ads, tpath):
        for r in results:
            verdict = r.get("verdict", "?").upper()
            reasons = "; ".join(r.get("reasons", [])) or r.get("error", "")
            self.tree.insert("", "end", values=(verdict, r.get("path", ""), reasons))
        self.persist_text.insert("end", f"Persistence findings: {len(persist)}\n" + "=" * 60 + "\n")
        for p in persist: self.persist_text.insert("end", f"[{p.get('type')}] {p.get('location')}: {p.get('entry')}\n")
        self.proc_text.insert("end", f"Suspicious processes: {len(procs)}\n" + "=" * 60 + "\n")
        for pr in procs: self.proc_text.insert("end", f"[PID {pr.get('pid')}] {pr.get('name')} -> {pr.get('path')}\n")
        self.net_text.insert("end", f"Suspicious connections: {len(network)}\n" + "=" * 60 + "\n")
        for n in network: self.net_text.insert("end", f"[{n.get('proto')}] {n.get('local')} -> {n.get('remote')} (PID {n.get('pid')}) {n.get('reason')}\n")
        self.browser_text.insert("end", f"Browser extensions: {len(browsers)}\n" + "=" * 60 + "\n")
        for b in browsers: self.browser_text.insert("end", f"[{b.get('browser','?')}] {b.get('extension_id') or b.get('name')} ({b.get('profile')})\n")
        self.hosts_text.insert("end", f"Hosts/DNS findings: {len(hosts)}\n" + "=" * 60 + "\n")
        for h in hosts: self.hosts_text.insert("end", f"[{h.get('type')}] {h.get('entry','')}\n")
        self.ads_text.insert("end", f"ADS findings: {len(ads)}\n" + "=" * 60 + "\n")
        for a in ads: self.ads_text.insert("end", f"{a.get('entry','')}\n")
        mal = sum(1 for r in results if r.get("verdict") == "malicious")
        susp = sum(1 for r in results if r.get("verdict") == "suspicious")
        self.status_var.set(f"Done. Malicious: {mal}, Suspicious: {susp}, Findings: {len(results)} | Persist:{len(persist)} Proc:{len(procs)} Net:{len(network)} Ext:{len(browsers)}")
        self.log(f"\nDone. Malicious: {mal}, Suspicious: {susp}, Findings: {len(results)}")
        self.log(f"Report: {tpath}")
        messagebox.showinfo("Scan complete", f"Malicious: {mal}\nSuspicious: {susp}\nFindings: {len(results)}\nPersist: {len(persist)} | Proc: {len(procs)} | Net: {len(network)}\nExt: {len(browsers)} | Hosts: {len(hosts)} | ADS: {len(ads)}\n\nReport:\n{tpath}")

    def _reset_buttons(self):
        self.scan_btn.config(state="normal"); self.cancel_btn.config(state="disabled")

    def quarantine_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Info", "Select a row first."); return
        for s in sel:
            path = self.tree.item(s, "values")[1]
            try:
                q = quarantine_file(path)
                self.log(f"Quarantined: {path} -> {q}")
                self.tree.set(s, "verdict", "QUARANTINED")
            except Exception as e:
                self.log(f"Quarantine failed: {e}")

    def copy_path(self):
        sel = self.tree.selection()
        if not sel: return
        path = self.tree.item(sel[0], "values")[1]
        self.clipboard_clear(); self.clipboard_append(path)

def main():
    app = App(); app.mainloop()

if __name__ == "__main__":
    main()
