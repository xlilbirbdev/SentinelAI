# SentinelAI

A host-based security monitoring tool. Real-time terminal dashboard with four panels:

| Panel | What it shows | Library |
|---|---|---|
| **PROCESSES** | Newly spawned (flagged `NEW`) + top resource users | psutil |
| **NETWORK** | Active inet connections with owning PID/process | psutil |
| **AUTH** | Recent login / sudo / privilege events, classified | platform-specific |
| **FILESYSTEM** | Create / modify / delete / move events in a watched dir | watchdog |

Stack: Python, [psutil](https://github.com/giampaolo/psutil), [Textual](https://textual.textualize.io/), [watchdog](https://github.com/gorakhargosh/watchdog), pywin32 (Windows only).

---

## Files

| File | Platform | Panels |
|---|---|---|
| `sentinelai_v1.py` | Linux / macOS / Windows | Processes, Network, Auth, Filesystem |
| `sentinelai_v2.py` | Linux / macOS | Processes, Auth, Filesystem |

---

## Install

```bash
python3 -m venv .venv

# Linux / macOS:
source .venv/bin/activate

# Windows (PowerShell):
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

### requirements.txt

```
psutil>=5.9
textual>=0.50
watchdog>=3.0
pywin32>=306; sys_platform == "win32"   # Windows only — safe to include everywhere
```

---

## Run

**Linux**

```bash
python3 sentinelai_v1.py                  # watch home dir, 2s refresh
python3 sentinelai_v1.py -w /etc -i 1     # watch /etc, refresh every 1s
sudo python3 sentinelai_v1.py             # full auth + network detail
```

**macOS**

```bash
python3 sentinelai_v1.py
sudo python3 sentinelai_v1.py             # required for network connections and auth
```

**Windows** — run from an Administrator terminal (Windows Terminal, not `cmd.exe`)

```powershell
python sentinelai_v1.py
python sentinelai_v1.py -w C:\Users\me\Documents -i 1
```

**Keys:** `q` quit · `r` force refresh

Without elevation the Auth panel shows a hint row instead of events, and the Network panel may omit process ownership. Everything else runs normally.

---

## Cross-platform design

`psutil` and `watchdog` are cross-platform, so three of the four panels need no per-OS code. The AUTH panel is the exception — every OS stores login events somewhere different, so each platform gets its own reader behind a shared interface.

### Linux

- Reads `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora)
- The file is usually `root:adm 0640`. To read it without sudo: `sudo usermod -aG adm "$USER"`, then log out and back in
- On systemd-only distros with no plain file, falls back to:

  ```
  journalctl --no-pager -n 50 SYSLOG_FACILITY=10
  ```

  (facility 10 = authpriv), or filters by `_COMM=sshd`, `_COMM=sudo`, `_COMM=login`

### macOS

- No `auth.log`. Queries the unified logging system through the `log` CLI:

  ```
  log show --style syslog --last 10m --predicate \
    'process == "sshd" OR process == "sudo" OR process == "loginwindow" \
     OR eventMessage CONTAINS[c] "authenticat"'
  ```

- The `--last` window is kept short; `log show` is slow over long ranges
- The predicate is passed as a single argv element rather than through a shell, avoiding `shell=True`

### Windows

- No syslog. Reads the **Security** event log through `pywin32` → `win32evtlog`

  | Event ID | Meaning | Label |
  |---|---|---|
  | 4624 | Successful logon | `OK` |
  | 4625 | Failed logon | `FAIL` |
  | 4672 | Special/elevated privileges | `PRIV` |
  | 4634 / 4647 | Logoff | `INFO` |
  | 4720 | User account created | `INFO` |

- Requires Administrator; admin status detected with `ctypes.windll.shell32.IsUserAnAdmin()`
- `win32evtlog` is imported lazily so the module still loads on Linux and macOS

### Event classification

Text-based readers classify each line into a label:

- `FAIL` — "failed password", "authentication failure", "invalid user"
- `OK` — "accepted", "session opened"
- `SUDO` — "sudo"
- `INFO` — everything else

---

## Elevation requirements

| OS | What needs elevation | How |
|---|---|---|
| Linux | Auth panel (`adm` group); some network ownership detail | `sudo usermod -aG adm "$USER"` or run with `sudo` |
| macOS | `psutil.net_connections()` raises `AccessDenied` without root; some `log` predicates too | `sudo python3 sentinelai_v1.py` |
| Windows | Security event log | Run terminal **as Administrator**. Use **Windows Terminal**, not legacy `cmd.exe` |

---

## Test checklist

| Panel | What to trigger | Expected result |
|---|---|---|
| Processes | Open a new app | It appears flagged `NEW` |
| Network | `python -m http.server` | LISTEN row + owning PID |
| Filesystem | `touch`/create/delete in watched dir | Event row appears |
| Auth (Linux) | Failed `sudo` attempt | `FAIL`/`SUDO` row |
| Auth (macOS) | Any `sudo` command | Row within `--last` window |
| Auth (Windows) | Lock/unlock or bad login | 4624/4625 rows (as admin) |

---

## Roadmap

- Alerting on repeated `FAIL` auth events or connections to new remote IPs
- JSON/structured event logging for later analysis
- Baseline + anomaly flagging for processes and outbound connections
