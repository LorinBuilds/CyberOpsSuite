# CyberOpsSuite

**A modular, cross-platform security toolkit for Windows and Linux administrators.**

CyberOpsSuite bundles seven independent security tools under a single,
consistent dashboard. Every module runs in its own process, uses the same
dark theme, and can also be launched standalone. Every module ships with a
built-in **How to Use** guide (per-page where applicable).

> **📌 A note on how this project was built**
>
> CyberOpsSuite was built through **vibe coding** — a collaborative,
> iterative process between a human and an AI assistant. The code was
> written, reviewed, and refined through natural conversation rather
> than traditional step-by-step planning.
>
> We believe in being transparent about this. The project works, but
> it is the product of human-AI collaboration, not a solo human effort.
> Contributions, bug reports, and constructive feedback are welcome.

---

## Modules

| Module | Purpose | Platform |
|--------|---------|----------|
| Firewall Manager | Manage firewall rules (netsh / ufw / nft / iptables) | Windows + Linux |
| Event Log Analyzer | Read Windows event logs, Linux journal, or JSON Lines | Windows + Linux |
| Network Mapper | Concurrent ICMP + TCP host discovery and port scanning | Windows + Linux |
| DHCP Lease Viewer | View local leases and query remote DHCP servers | Windows + Linux |
| Server Monitor | Monitor and control local services with health score and donut chart | Windows + Linux |
| VPN Manager | Manage VLESS/VMess profiles with Xray-core and Smart Auto-Switch | Windows + Linux |
| IP Rotator | Change your public IP via the Tor network | Windows + Linux |

---

## Key Features

- **Unified dark dashboard** with live system status, global stats, and recent activity
- **Built-in How to Use guide** in every module (per-page for multi-page modules)
- **Thread-based operations** — the UI never freezes
- **Read-only by default** — no module modifies remote systems without explicit action
- **Cross-platform** — Windows 10/11/Server 2019+ and Linux (systemd-based)
- **Logging to AppData** — every module writes a log file for troubleshooting
- **Desktop notifications** for critical events (Server Monitor)
- **Smart Auto-Switch** for VPN Manager — tests latency and switches to the fastest server
- **Live speed measurement** for VPN Manager (down/up in Mbps)
- **Health score & donut chart** for Server Monitor
- **Scan history with comparison** for Network Mapper
- **Remote DHCP queries** via WinRM (Windows) or SSH (Linux)
- **Multiple export formats** — JSON, CSV, HTML

---

## Quick Start

### Dashboard (recommended)

    python -m dashboard.main

### Single module

    python -m firewall_manager.gui.main
    python -m event_log_analyzer.gui.main
    python -m network_mapper.gui.main
    python -m dhcp_lease_viewer.gui.main
    python -m server_monitor.gui.main
    python -m vpn_manager.gui.main
    python -m ip_rotator.gui.main

---

## Requirements

* Python 3.10+ (tested on 3.14)
* pip

Install dependencies:

    pip install -r requirements.txt

### Optional packages

| Package | Used by | Purpose |
|---------|---------|---------|
| `plyer` | Server Monitor | Desktop notifications for critical service stops |
| `paramiko` | DHCP Lease Viewer | Password-based SSH (Linux remote backend) |
| `stem` | IP Rotator | Tor controller integration |

### Per-module requirements

| Module | Windows | Linux |
|--------|---------|-------|
| Firewall Manager | Admin privileges | sudo + ufw/nft/iptables |
| Event Log Analyzer | PowerShell | journalctl + systemd-journal group |
| Network Mapper | -- | -- |
| DHCP Lease Viewer | PowerShell + WinRM (RSAT-DHCP for remote) | systemd-networkd + SSH |
| Server Monitor | Admin for control | sudo for control |
| VPN Manager | xray.exe in bin/ | xray in bin/ |
| IP Rotator | Tor + ControlPort | Tor + ControlPort |

---

## Project Structure

    CyberOpsSuite/
    |-- dashboard/              Launcher for all modules
    |-- core/                   Shared code
    |   |-- theme.py
    |   |-- gui/treeview_style.py
    |   |-- utils/
    |       |-- icons.py
    |       |-- paths.py
    |       |-- subprocess_utils.py
    |-- firewall_manager/
    |-- event_log_analyzer/
    |-- network_mapper/
    |-- dhcp_lease_viewer/
    |-- server_monitor/
    |-- vpn_manager/
    |-- ip_rotator/
    |-- assets/icons/
    |-- bin/                    Xray-core + wintun + geoip/geosite
    |-- data/                   Sample data
    |-- exports/                Runtime exports
    |-- requirements.txt
    |-- README.md
    |-- README.FA.md

---

## Configuration

Per-user configuration:

| Platform | Location |
|----------|----------|
| Windows | %APPDATA%\CyberOpsSuite\<Module>\ |
| Linux   | ~/.config/CyberOpsSuite/<Module>/ |

The data/ directory contains sample files for reference.

---

## Building an Executable

    pip install pyinstaller
    python build.py

Output is placed in dist/.

---

## Platform Support

* Windows 10 / 11 / Server 2019+
* Linux (systemd-based)
* macOS -- not supported

---

## Responsible Use

Use CyberOpsSuite only on systems you own or have explicit permission
to assess. Scanning, firewall modification, and log analysis can have
legal and operational consequences on networks you do not administer.

---

## Extending the Suite

1. Create a package with core/, gui/main.py, api/main.py, cli/main.py
2. Import shared helpers from core.theme, core.utils.icons, core.utils.paths
3. Add an entry to the TOOLS list in dashboard/main.py
4. Add the module's EXE name to MODULE_TO_EXE in dashboard/main.py (if you want EXE mode)
5. Add a `How to Use` guide following the pattern in other modules

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| F5 / Ctrl+R | Refresh current page |
| F1 | Open About |
| Enter | Connect / Open details |
| Delete | Remove selected item |
| Escape | Close dialogs / clear filters |
| Ctrl+O | Open file (Event Log Analyzer) |
| Ctrl+F | Focus search |
| Ctrl+L | Clear filters |
| Ctrl+E | Export CSV |

---

## License

Provided as-is for educational and authorized administrative use.
Third-party binaries (xray, wintun) are covered by their own
licenses -- see bin/LICENSE and bin/LICENSE-wintun.txt.

---

## Acknowledgements

* CustomTkinter -- https://github.com/TomSchimansky/CustomTkinter
* Xray-core -- https://github.com/XTLS/Xray-core
* Wintun -- https://www.wintun.net/
* FastAPI -- https://fastapi.tiangolo.com/
* Plyer -- https://github.com/kivy/plyer
* Paramiko -- https://www.paramiko.org/
* Stem -- https://stem.torproject.org/