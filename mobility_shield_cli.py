#!/usr/bin/env python3
"""Mobility Shield CLI"""
import argparse, sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mobility_shield import (load_config, save_config, scan_path, scan_persistence,
                             scan_processes, scan_network, scan_hosts, scan_browsers,
                             scan_ads, save_report, quarantine_file, quick_scan_targets,
                             APP_DIR, QUARANTINE_DIR, REPORTS_DIR)

def main():
    parser = argparse.ArgumentParser(prog="mobility-shield", description="Mobility Shield - lightweight scanner")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="Scan a file or folder")
    p_scan.add_argument("target", nargs="?", help="File or directory to scan")
    p_scan.add_argument("--profile", choices=["quick", "full", "custom"], default="custom")
    p_scan.add_argument("--vt", action="store_true", help="Enable VirusTotal lookup")
    p_scan.add_argument("--persist", action="store_true", help="Also scan persistence")
    p_scan.add_argument("--procs", action="store_true", help="Also scan processes")
    p_scan.add_argument("--network", action="store_true", help="Also scan network")
    p_scan.add_argument("--browsers", action="store_true", help="Also scan browser extensions")
    p_scan.add_argument("--hosts", action="store_true", help="Also check hosts/DNS")
    p_scan.add_argument("--ads", action="store_true", help="Also scan ADS")
    p_scan.add_argument("--quarantine", action="store_true", help="Quarantine malicious files")
    p_scan.add_argument("--json", action="store_true", help="Print JSON results")

    sub.add_parser("quick", help="Quick scan (Downloads, Desktop, Temp, Startup)")
    sub.add_parser("full", help="Full scan of user profile + persistence + network + browsers")
    sub.add_parser("persist", help="Scan persistence locations only")
    sub.add_parser("procs", help="Scan running processes only")
    sub.add_parser("network", help="Scan network connections")
    sub.add_parser("browsers", help="Scan browser extensions")
    sub.add_parser("hosts", help="Check hosts file and DNS")

    p_cfg = sub.add_parser("config", help="Show/set config")
    p_cfg.add_argument("--vt-key", help="Set VirusTotal API key")

    p_q = sub.add_parser("quarantine", help="Quarantine a file")
    p_q.add_argument("file")

    args = parser.parse_args()
    cfg = load_config()

    if args.cmd == "config":
        if args.vt_key:
            cfg["vt_api_key"] = args.vt_key
            save_config(cfg)
            print("VirusTotal API key saved.")
        else:
            print(f"Config file: {CONFIG_FILE if False else APP_DIR / 'config.json'}")
            print(f"VT API key: {'set' if cfg.get('vt_api_key') else 'not set'}")
            print(f"Modules: {json.dumps(cfg.get('modules', {}), indent=2)}")
        return

    if args.cmd == "quarantine":
        dest = quarantine_file(args.file)
        print(f"Quarantined -> {dest}")
        return

    if args.cmd == "persist":
        res = scan_persistence()
        print(f"Persistence findings: {len(res)}")
        for r in res:
            print(f"  [{r['type']}] {r['location']}: {r['entry']}")
        return

    if args.cmd == "procs":
        res = scan_processes()
        print(f"Suspicious processes: {len(res)}")
        for r in res:
            print(f"  [PID {r['pid']}] {r['name']} -> {r['path']}")
        return

    if args.cmd == "network":
        res = scan_network()
        print(f"Suspicious connections: {len(res)}")
        for r in res:
            print(f"  [{r['proto']}] {r['local']} -> {r['remote']} (PID {r['pid']}) {r['reason']}")
        return

    if args.cmd == "browsers":
        res = scan_browsers()
        print(f"Browser extensions: {len(res)}")
        for r in res:
            print(f"  [{r.get('browser','?')}] {r.get('extension_id') or r.get('name')} ({r.get('profile')})")
        return

    if args.cmd == "hosts":
        res = scan_hosts()
        print(f"Hosts/DNS findings: {len(res)}")
        for r in res:
            print(f"  [{r['type']}] {r.get('entry','')}")
        return

    if args.cmd in ("quick", "full"):
        if args.cmd == "quick":
            targets = quick_scan_targets()
        else:
            targets = [str(Path.home())]
        all_results = []
        persist = []; procs = []; network = []; browsers = []; hosts = []; ads = []
        for t in targets:
            print(f"\n=== Scanning {t} ===")
            r = scan_path(t, cfg, progress_cb=lambda i,tot,p: print(f"\r[{i}/{tot}] {p[:70].encode('ascii','replace').decode()}", end="", flush=True))
            print()
            all_results.extend(r)
        # extra modules based on profile
        if args.cmd == "full":
            persist = scan_persistence()
            procs = scan_processes()
            network = scan_network()
            browsers = scan_browsers()
            hosts = scan_hosts()
            # ADS on quick targets
            for t in quick_scan_targets():
                ads.extend(scan_ads(t))
        jpath, tpath = save_report(all_results, persist, procs, " + ".join(targets),
                                   extra={"network": network, "browsers": browsers,
                                          "hosts": hosts, "ads": ads})
        _print_summary(all_results, persist, procs, network, browsers, hosts, ads, tpath)
        if any(r.get("verdict") == "malicious" for r in all_results):
            sys.exit(2)
        if all_results:
            sys.exit(1)
        return

    if args.cmd == "scan":
        # determine modules
        if args.profile == "quick":
            args.persist = True; args.procs = True
        if args.profile == "full":
            args.persist = True; args.procs = True; args.network = True
            args.browsers = True; args.hosts = True; args.ads = True
        target = args.target
        if not target:
            print("Please provide a target.")
            return
        print(f"Mobility Shield scanning: {target}")
        def progress(i, total, path):
            print(f"\r[{i}/{total}] {path[:80].encode('ascii','replace').decode():<80}", end="", flush=True)
        results = scan_path(target, cfg, progress_cb=progress)
        print()
        persist = scan_persistence() if args.persist else []
        procs = scan_processes() if args.procs else []
        network = scan_network() if args.network else []
        browsers = scan_browsers() if args.browsers else []
        hosts = scan_hosts() if args.hosts else []
        ads = scan_ads(target) if args.ads else []
        if args.quarantine:
            for r in results:
                if r.get("verdict") == "malicious":
                    try:
                        q = quarantine_file(r["path"])
                        print(f"  Quarantined: {r['path']} -> {q}")
                    except Exception as e:
                        print(f"  Quarantine failed: {e}")
        jpath, tpath = save_report(results, persist, procs, target,
                                   extra={"network": network, "browsers": browsers,
                                          "hosts": hosts, "ads": ads})
        _print_summary(results, persist, procs, network, browsers, hosts, ads, tpath)
        if args.json:
            print(json.dumps(results, indent=2, ensure_ascii=False))
        if any(r.get("verdict") == "malicious" for r in results):
            sys.exit(2)
        if results:
            sys.exit(1)
        return

    parser.print_help()

def _print_summary(results, persist, procs, network, browsers, hosts, ads, tpath):
    print(f"\nFile findings: {len(results)}")
    for r in results:
        print(f"  [{r.get('verdict','?').upper()}] {r.get('path')}")
        for reason in r.get("reasons", []):
            print(f"     - {reason}")
    if persist:
        print(f"\nPersistence: {len(persist)}")
    if procs:
        print(f"Suspicious processes: {len(procs)}")
    if network:
        print(f"Suspicious connections: {len(network)}")
    if browsers:
        print(f"Browser extensions: {len(browsers)}")
    if hosts:
        print(f"Hosts/DNS: {len(hosts)}")
    if ads:
        print(f"ADS: {len(ads)}")
    print(f"\nReport: {tpath}")

if __name__ == "__main__":
    main()
