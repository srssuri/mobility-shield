# Mobility Shield - Lightweight Security Scanner

Part of the **Mobility-os** project. A lightweight, on-demand security scanner
that complements (does not replace) Windows Defender. Low resource usage:
no background daemon, no kernel driver, single-threaded, on-demand only.

## Features
- SHA-256 hashing + **VirusTotal** lookup (optional, free API key)
- Offline signature database (`mobility_shield_sigs.txt`)
- Heuristics: double extensions, suspicious executables in user-writable
  locations, high entropy (packing), unusually small executables, magic-byte
  mismatch (masquerading)
- Persistence scan: Run keys, Startup folders, scheduled tasks, services,
  WMI event subscriptions, autorun.inf
- Process scan: suspicious running processes + command lines
- Network scan: suspicious outbound connections (known bad ports)
- Browser extension scan (Chrome/Edge/Brave/Firefox)
- Hosts file checks (suspicious redirects)
- Alternate Data Streams (ADS) detection
- Quarantine with metadata
- Quick / Full / Custom scan profiles
- JSON + text reports
- CLI + GUI (tkinter)

## Usage
Double-click `MobilityShield.bat` to open the GUI, or use the CLI:

```
python mobility_shield_cli.py quick
python mobility_shield_cli.py full
python mobility_shield_cli.py scan C:\Users\You\Downloads
python mobility_shield_cli.py scan C:\ --persist --procs --network --browsers --hosts --ads
python mobility_shield_cli.py persist
python mobility_shield_cli.py procs
python mobility_shield_cli.py network
python mobility_shield_cli.py browsers
python mobility_shield_cli.py hosts
python mobility_shield_cli.py config --vt-key YOUR_KEY
python mobility_shield_cli.py quarantine C:\path\to\suspicious.exe
```

## VirusTotal API key (optional)
Get a free key at https://www.virustotal.com/gui/join-us, then:
```
python mobility_shield_cli.py config --vt-key YOUR_KEY
```
Or set env var `MOBILITY_VT_KEY`.

## Exit codes
- 0 = clean
- 1 = suspicious findings
- 2 = malicious findings

## Files
- `mobility_shield.py` - core engine
- `mobility_shield_cli.py` - CLI
- `mobility_shield_gui.py` - GUI (tkinter)
- `mobility_shield_sigs.txt` - offline signature DB
- `MobilityShield.bat` - Windows launcher

## Limitations
This is NOT a real-time antivirus. It does not install kernel drivers, does not
monitor the filesystem in real time, and does not provide the protection level
of Windows Defender / a commercial AV. Use it as a second-opinion / cleanup tool.
