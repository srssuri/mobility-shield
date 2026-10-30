"""
Mobility Shield - lightweight on-demand security scanner
Part of the Mobility-os project. Complements (does not replace) Windows Defender.

Features:
  - SHA-256 hashing + VirusTotal lookup (optional, needs free API key)
  - Offline signature DB (known-bad hashes)
  - Heuristics: suspicious extensions, double extensions, high entropy,
    executables in user-writable locations, magic-byte mismatch
  - Persistence scan: Run keys, Startup folders, scheduled tasks, services,
    WMI event subscriptions, autorun.inf
  - Process scan: suspicious running processes + command lines
  - Network scan: suspicious outbound connections
  - Browser extension scan (Chrome/Edge/Firefox)
  - Hosts file / DNS checks
  - Alternate Data Streams (ADS) detection
  - Quarantine with metadata
  - Quick / Full / Custom scan profiles
  - JSON + text reports
"""
import os, sys, json, hashlib, shutil, subprocess, threading, time, math, string
from pathlib import Path

APP_NAME = "Mobility Shield"
APP_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "MobilityShield"
QUARANTINE_DIR = APP_DIR / "Quarantine"
CONFIG_FILE = APP_DIR / "config.json"
REPORTS_DIR = APP_DIR / "Reports"
SIGS_FILE = Path(__file__).with_name("mobility_shield_sigs.txt")

SUSPICIOUS_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                  ".hta", ".com", ".pif", ".wsf", ".wsh", ".msi", ".jar"}
USER_WRITABLE = ("downloads", "temp", "appdata", "desktop", "documents", "public")

# ---------- config ----------
def load_config():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    cfg = {"vt_api_key": "", "max_file_size_mb": 50, "scan_archives": False,
           "modules": {"heuristics": True, "virustotal": False, "persistence": True,
                       "processes": True, "network": True, "browsers": True,
                       "hosts": True, "ads": True, "magic": True, "services": True}}
    if CONFIG_FILE.exists():
        try:
            loaded = json.loads(CONFIG_FILE.read_text())
            cfg.update({k: v for k, v in loaded.items() if k != "modules"})
            if "modules" in loaded:
                cfg["modules"].update(loaded["modules"])
        except Exception:
            pass
    env_key = os.environ.get("MOBILITY_VT_KEY") or os.environ.get("VT_API_KEY")
    if env_key:
        cfg["vt_api_key"] = env_key
    return cfg

def save_config(cfg):
    APP_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

# ---------- signatures ----------
def load_sigs():
    sigs = {}
    if SIGS_FILE.exists():
        for line in SIGS_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) >= 1:
                sigs[parts[0].lower()] = parts[1] if len(parts) > 1 else "Known malware"
    return sigs

# ---------- hashing ----------
def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()

def file_entropy(path, sample=65536):
    try:
        with open(path, "rb") as f:
            data = f.read(sample)
    except Exception:
        return 0.0
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

# ---------- heuristics ----------
def heuristic_findings(path):
    findings = []
    p = Path(path)
    name = p.name.lower()
    ext = p.suffix.lower()
    parent = str(p.parent).lower()
    parts = name.split(".")
    if len(parts) >= 3 and parts[-1] in ("exe", "scr", "bat", "cmd", "com", "pif", "msi"):
        findings.append("Double extension (masquerading)")
    # Only flag inherently dangerous executable types in user-writable locations
    # (.dll is too common in temp/update caches to flag by location alone)
    USER_DANGER_EXT = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                       ".hta", ".com", ".pif", ".wsf", ".wsh", ".msi", ".jar"}
    if ext in USER_DANGER_EXT and any(d in parent for d in USER_WRITABLE):
        findings.append(f"Suspicious executable in user-writable location ({ext})")
    if ext in (".exe", ".dll", ".scr") and p.is_file():
        try:
            if 4096 < p.stat().st_size < 5 * 1024 * 1024:
                if file_entropy(path) > 7.6:
                    findings.append("High entropy (possible packing/encryption)")
        except Exception:
            pass
    if ext in (".exe", ".scr") and p.is_file():
        try:
            if 0 < p.stat().st_size < 10240:
                findings.append("Unusually small executable")
        except Exception:
            pass
    return findings

# Extensions that are legitimately PE (Windows executables/libraries/resources)
PE_EXT = {".exe", ".dll", ".scr", ".com", ".sys", ".drv", ".ocx", ".cpl",
          ".mui", ".mun", ".mof", ".efi"}
ZIP_EXT = {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".apk", ".vsix", ".whl",
           ".msix", ".xpi", ".crx", ".epub", ".odt", ".nupkg"}

def magic_mismatch(path):
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except Exception:
        return None
    ext = Path(path).suffix.lower()
    is_pe = head.startswith(b"MZ")
    is_zip = head.startswith(b"PK")
    # PE magic but non-executable extension -> masquerading as document
    if is_pe and ext and ext not in PE_EXT:
        return f"File has executable (PE) magic but extension is {ext} (possible masquerading)"
    # executable extension but not PE -> suspicious (unless script)
    if ext in (".exe", ".dll", ".scr", ".com") and not is_pe:
        return f"File has {ext} extension but is not a valid PE executable"
    return None

# ---------- VirusTotal ----------
def vt_lookup(sha256, api_key, timeout=20):
    if not api_key:
        return None
    try:
        import urllib.request, urllib.error
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return stats
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"not_found": True}
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}

# ---------- persistence scan ----------
def scan_persistence():
    findings = []
    run_keys = [
        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKCU Policies Run"),
        (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKLM Policies Run"),
    ]
    for key, label in run_keys:
        try:
            out = subprocess.check_output(["reg", "query", key], stderr=subprocess.DEVNULL,
                                          text=True, encoding="utf-8", errors="ignore")
            for line in out.splitlines():
                line = line.strip()
                if not line or "HKEY" in line or line.startswith(key):
                    continue
                if "REG_" in line:
                    findings.append({"type": "registry_run", "location": label, "entry": line})
        except Exception:
            pass
    # Startup folders
    startup_dirs = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
        Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "Microsoft/Windows/Start Menu/Programs/StartUp",
    ]
    for d in startup_dirs:
        if d.exists():
            for f in d.iterdir():
                findings.append({"type": "startup_folder", "location": str(d), "entry": f.name})
    # Scheduled tasks (non-Microsoft, enabled)
    try:
        out = subprocess.check_output(["schtasks", "/query", "/fo", "CSV", "/nh"], stderr=subprocess.DEVNULL,
                                     text=True, encoding="utf-8", errors="ignore")
        for line in out.splitlines():
            if not line.strip():
                continue
            cols = [c.strip('"') for c in line.split('","')]
            if len(cols) < 3:
                continue
            name, status = cols[0], cols[2] if len(cols) > 2 else ""
            nl = name.lower()
            if any(k in nl for k in ("microsoft", "windows", "office", "adobe", "google", "mozilla", "intel", "nvidia", "amd")):
                continue
            if "ready" in status.lower() or "running" in status.lower():
                findings.append({"type": "scheduled_task", "location": "Task Scheduler", "entry": name})
    except Exception:
        pass
    # Services (non-Microsoft, running)
    try:
        out = subprocess.check_output(["sc", "query", "state=", "all"], stderr=subprocess.DEVNULL,
                                     text=True, encoding="utf-8", errors="ignore")
        current = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                current = line.split(":", 1)[1].strip()
            elif line.startswith("STATE") and current:
                if "RUNNING" in line.upper():
                    cn = current.lower()
                    if not any(k in cn for k in ("windows", "microsoft", "wuauserv", "bits", "cryptsvc",
                                                  "dcomlaunch", "rpcss", "lsass", "spooler", "w32time",
                                                  "winmgmt", "eventlog", "plugplay", "profsvc", "schedule",
                                                  "sens", "shellhwdetection", "themes", "userprof", "wscsvc",
                                                  "mpssvc", "bensvc", "nlasvc", "netprofm", "nsi", "dhcp",
                                                  "dnscache", "lanmanserver", "lanmanworkstation", "netlogon",
                                                  "samss", "seclogon", "w32time", "winhttp", "wscsvc")):
                        findings.append({"type": "service", "location": "Services", "entry": current})
                current = None
    except Exception:
        pass
    # WMI persistence
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-WmiObject -Namespace root\\Subscription -Class __EventFilter 2>$null | Select-Object Name,Query | ConvertTo-Csv -NoTypeInformation"],
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore", timeout=30)
        for line in out.splitlines()[1:]:
            if line.strip():
                findings.append({"type": "wmi_event_filter", "location": "WMI", "entry": line.strip()})
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             "Get-WmiObject -Namespace root\\Subscription -Class CommandLineEventConsumer 2>$null | Select-Object Name,CommandLineTemplate | ConvertTo-Csv -NoTypeInformation"],
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore", timeout=30)
        for line in out.splitlines()[1:]:
            if line.strip():
                findings.append({"type": "wmi_consumer", "location": "WMI", "entry": line.strip()})
    except Exception:
        pass
    # autorun.inf on drives
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        for name in ("autorun.inf", "autorun.ini"):
            p = Path(f"{letter}:/{name}")
            if p.exists():
                findings.append({"type": "autorun", "location": f"{letter}:", "entry": str(p)})
    return findings

# ---------- process scan ----------
def scan_processes():
    findings = []
    suspicious_path_markers = ("\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\local\\temp",
                              "\\public\\", "\\users\\public")
    try:
        out = subprocess.check_output(
            ["wmic", "process", "get", "Name,ProcessId,ExecutablePath,CommandLine", "/format:csv"],
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore"
        )
        for line in out.splitlines():
            if not line.strip() or line.startswith("Node"):
                continue
            cols = line.split(",")
            if len(cols) < 5:
                continue
            exe = cols[1].strip() if len(cols) > 1 else ""
            name = cols[2].strip() if len(cols) > 2 else ""
            pid = cols[3].strip() if len(cols) > 3 else ""
            cmd = cols[4].strip() if len(cols) > 4 else ""
            if not exe:
                continue
            el = exe.lower()
            reasons = []
            if any(m in el for m in suspicious_path_markers):
                reasons.append("Running from temp/user-writable path")
            # suspicious command line patterns
            cl = cmd.lower()
            if any(k in cl for k in ("powershell -enc", "powershell -e ", "iex(", "downloadstring",
                                      "frombase64string", "hidden", "-w hidden", "bypass")):
                reasons.append("Suspicious command-line (encoded/bypass)")
            if reasons:
                findings.append({"type": "process", "pid": pid, "name": name, "path": exe,
                                 "cmd": cmd, "reason": "; ".join(reasons)})
    except Exception:
        pass
    return findings

# ---------- network scan ----------
def scan_network():
    findings = []
    suspicious_ports = {4444, 5555, 6666, 1337, 31337, 8080, 9001, 9050}
    try:
        out = subprocess.check_output(["netstat", "-ano"], stderr=subprocess.DEVNULL,
                                     text=True, encoding="utf-8", errors="ignore")
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            local = parts[1]
            remote = parts[2]
            state = parts[3] if len(parts) >= 4 else ""
            pid = parts[-1]
            if proto not in ("TCP", "UDP"):
                continue
            if state not in ("ESTABLISHED", "LISTENING", ""):
                continue
            # parse remote port
            try:
                rport = int(remote.rsplit(":", 1)[-1])
            except ValueError:
                rport = 0
            if rport in suspicious_ports:
                findings.append({"type": "network", "proto": proto, "local": local,
                                 "remote": remote, "state": state, "pid": pid,
                                 "reason": f"Suspicious remote port {rport}"})
            # connections to non-standard with LISTENING on high ports from unknown
            if state == "LISTENING" and ":" in local:
                try:
                    lport = int(local.rsplit(":", 1)[-1])
                except ValueError:
                    lport = 0
                if lport > 1024 and lport not in (135, 445, 3389, 5985, 5986, 80, 443, 8080):
                    # only flag if process suspicious; collect for info
                    pass
    except Exception:
        pass
    # dedupe
    seen = set()
    uniq = []
    for f in findings:
        key = (f["proto"], f["local"], f["remote"], f["pid"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    return uniq

# ---------- hosts file ----------
def scan_hosts():
    findings = []
    hosts = Path("C:/Windows/System32/drivers/etc/hosts")
    if not hosts.exists():
        return findings
    try:
        lines = hosts.read_text(errors="ignore").splitlines()
    except Exception:
        return findings
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        # flag redirects of well-known domains
        parts = s.split()
        if len(parts) >= 2:
            ip = parts[0]
            domains = parts[1:]
            for d in domains:
                dl = d.lower()
                if ip not in ("127.0.0.1", "::1", "0.0.0.0") and any(k in dl for k in ("google", "microsoft", "facebook", "apple", "paypal", "bank")):
                    findings.append({"type": "hosts", "entry": s, "reason": "Suspicious redirect of known domain"})
                if ip.startswith("0.0.0.0") and any(k in dl for k in ("update", "telemetry")):
                    pass
    return findings

# ---------- browser extensions ----------
def scan_browsers():
    findings = []
    # Chrome / Edge / Brave extension dirs
    bases = []
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    bases.append(("Chrome", local / "Google/Chrome/User Data"))
    bases.append(("Edge", local / "Microsoft/Edge/User Data"))
    bases.append(("Brave", local / "BraveSoftware/Brave-Browser/User Data"))
    for browser, base in bases:
        if not base.exists():
            continue
        for profile in base.iterdir():
            if not profile.is_dir() or not profile.name.startswith(("Default", "Profile")):
                continue
            ext_dir = profile / "Extensions"
            if not ext_dir.exists():
                continue
            for ext in ext_dir.iterdir():
                if not ext.is_dir():
                    continue
                # version subdirs
                versions = [v for v in ext.iterdir() if v.is_dir()]
                if not versions:
                    continue
                findings.append({"type": "browser_extension", "browser": browser,
                                 "profile": profile.name, "extension_id": ext.name,
                                 "versions": len(versions), "reason": "Installed extension (review manually)"})
    # Firefox
    roaming = Path(os.environ.get("APPDATA", ""))
    ff = roaming / "Mozilla/Firefox/Profiles"
    if ff.exists():
        for prof in ff.iterdir():
            if not prof.is_dir():
                continue
            addons = prof / "extensions"
            if addons.exists():
                for a in addons.iterdir():
                    findings.append({"type": "firefox_extension", "profile": prof.name,
                                     "name": a.name, "reason": "Installed extension (review manually)"})
    return findings

# ---------- ADS ----------
def scan_ads(target):
    findings = []
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command",
             f'Get-ChildItem -Path "{target}" -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {{ $s=$_.FullName; Get-Item $s -Stream * -ErrorAction SilentlyContinue | Where-Object Stream -ne ":$DATA" | ForEach-Object {{ "$s`:$($_.Stream)" }} }}'],
            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="ignore", timeout=120)
        for line in out.splitlines():
            if line.strip():
                findings.append({"type": "ads", "entry": line.strip(), "reason": "Alternate Data Stream detected"})
    except Exception:
        pass
    return findings

# ---------- magic mismatch in scan ----------
def scan_file_magic(path):
    mm = magic_mismatch(path)
    if mm:
        return [{"type": "magic_mismatch", "path": str(path), "reason": mm}]
    return []

# ---------- quarantine ----------
def quarantine_file(path):
    p = Path(path)
    APP_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    dest = QUARANTINE_DIR / (p.name + ".quarantined")
    i = 1
    while dest.exists():
        dest = QUARANTINE_DIR / f"{p.name}.{i}.quarantined"
        i += 1
    meta = {"original": str(p), "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "sha256": sha256_file(p) if p.exists() else ""}
    shutil.move(str(p), str(dest))
    (dest.with_suffix(dest.suffix + ".json")).write_text(json.dumps(meta, indent=2))
    return str(dest)

# ---------- quick scan targets ----------
def quick_scan_targets():
    targets = []
    home = Path.home()
    for d in ("Downloads", "Desktop", "Documents"):
        p = home / d
        if p.exists():
            targets.append(str(p))
    for t in (os.environ.get("TEMP", ""), "C:/Windows/Temp"):
        if t and Path(t).exists():
            targets.append(t)
    # startup folders
    targets.append(str(Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup"))
    return targets

# ---------- scanner core ----------
def scan_path(target, cfg, progress_cb=None, cancel_flag=None, modules=None):
    if modules is None:
        modules = cfg.get("modules", {})
    target = Path(target)
    sigs = load_sigs()
    vt_key = cfg.get("vt_api_key", "") if modules.get("virustotal", False) else ""
    max_bytes = cfg.get("max_file_size_mb", 50) * 1024 * 1024
    results = []
    files = []
    if target.is_file():
        files = [target]
    else:
        for root, dirs, fnames in os.walk(target):
            dirs[:] = [d for d in dirs if d.lower() not in ("windows", "winsxs", "system32", "$recycle.bin",
                                                          "node_modules", ".git", "steam", "steamapps")]
            for fn in fnames:
                files.append(Path(root) / fn)
    total = len(files)
    for i, f in enumerate(files):
        if cancel_flag and cancel_flag.is_set():
            break
        if progress_cb:
            progress_cb(i + 1, total, str(f))
        try:
            if not f.is_file():
                continue
            size = f.stat().st_size
            if size == 0 or size > max_bytes:
                continue
            sha = sha256_file(f)
            verdict = "clean"
            reasons = []
            if sha in sigs:
                verdict = "malicious"
                reasons.append(f"Known signature: {sigs[sha]}")
            if modules.get("heuristics", True):
                hf = heuristic_findings(f)
                if hf:
                    if verdict == "clean":
                        verdict = "suspicious"
                    reasons.extend(hf)
            if modules.get("magic", True):
                mm = magic_mismatch(f)
                if mm:
                    if verdict == "clean":
                        verdict = "suspicious"
                    reasons.append(mm)
            vt_stats = None
            if vt_key and (f.suffix.lower() in SUSPICIOUS_EXT or verdict != "clean"):
                vt_stats = vt_lookup(sha, vt_key)
                if isinstance(vt_stats, dict):
                    if vt_stats.get("malicious", 0) and vt_stats.get("malicious", 0) > 0:
                        verdict = "malicious"
                        reasons.append(f"VirusTotal: {vt_stats.get('malicious',0)}/{sum(vt_stats.values())} engines flagged")
                    elif "error" in vt_stats:
                        reasons.append(f"VT error: {vt_stats['error']}")
            if verdict != "clean":
                results.append({"path": str(f), "sha256": sha, "size": size,
                                "verdict": verdict, "reasons": reasons, "vt": vt_stats})
        except (PermissionError, OSError):
            continue
        except Exception as e:
            results.append({"path": str(f), "error": str(e)})
    return results

def save_report(results, persist, procs, target, extra=None):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    extra = extra or {}
    ts = time.strftime("%Y%m%d_%H%M%S")
    report = {"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "target": str(target),
              "file_findings": results, "persistence": persist, "processes": procs, "extra": extra}
    json_path = REPORTS_DIR / f"report_{ts}.json"
    txt_path = REPORTS_DIR / f"report_{ts}.txt"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    lines = [f"Mobility Shield Report - {report['timestamp']}", f"Target: {target}", "",
             f"File findings: {len(results)}", "-" * 60]
    for r in results:
        lines.append(f"[{r.get('verdict','?').upper()}] {r.get('path')}")
        for reason in r.get("reasons", []):
            lines.append(f"   - {reason}")
    lines += ["", f"Persistence findings: {len(persist)}", "-" * 60]
    for p in persist:
        lines.append(f"[{p.get('type')}] {p.get('location')}: {p.get('entry')}")
    lines += ["", f"Suspicious processes: {len(procs)}", "-" * 60]
    for pr in procs:
        lines.append(f"[PID {pr.get('pid')}] {pr.get('name')} -> {pr.get('path')}")
    for key, val in extra.items():
        lines += ["", f"=== {key} ({len(val)}) ===", "-" * 60]
        for v in val:
            lines.append(str(v))
    txt_path.write_text("\n".join(lines), encoding="utf-8")
    return str(json_path), str(txt_path)
