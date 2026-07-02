# SentinelAI — Master Reference

A host-based security monitoring tool. Real-time terminal dashboard with four panels:

| Panel | What it shows | Library |
|---|---|---|
| **PROCESSES** | Newly spawned (flagged `NEW`) + top resource users | psutil |
| **NETWORK** | Active inet connections with owning PID/process | psutil |
| **AUTH** | Recent login / sudo / privilege events, classified | platform-specific |
| **FILESYSTEM** | Create / modify / delete / move events in a watched dir | watchdog |

Stack: Python, [psutil](https://github.com/giampaolo/psutil), [Textual](https://textual.textualize.io/), [watchdog](https://github.com/gorakhargosh/watchdog), pywin32 (Windows only).

> **Note:** `sentinelai_v2.py` (three-panel, no NETWORK) is intended for **Linux/macOS** use.

---

## Two versions in this repo

| File | Status | Notes |
|---|---|---|
| `files/sentinelai.py` | **Scaffold / rebuild target** | Fully commented skeleton with `raise NotImplementedError` stubs — this is what you build from |
| `sentinelai/sentinelai/sentinelai.py` | **Working Linux implementation** | Fully functional, Linux-only |

The scaffold is the cross-platform rewrite; the working file is your reference implementation.

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

### requirements.txt (cross-platform version)

```
psutil>=5.9
textual>=0.50
watchdog>=3.0
pywin32>=306; sys_platform == "win32"   # Windows only — safe to include everywhere
```

---

## Run

```bash
python sentinelai.py                  # watch home dir, 2s refresh
python sentinelai.py -w /etc -i 1    # watch /etc, refresh every 1s
```

**Keys:** `q` quit · `r` force refresh

---

## Cross-platform strategy

`psutil` and `watchdog` are already cross-platform. **Three of four panels need no per-OS code.**
The AUTH panel is your only real work — each OS stores login events in a completely different place.

### Linux
- Plain log file: `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora)
- File is usually `root:adm 0640`. To read without sudo: `sudo usermod -aG adm "$USER"` then log out/in
- On systemd-only distros with no plain file, fall back to:
  ```
  journalctl --no-pager -n 50 SYSLOG_FACILITY=10
  ```
  (facility 10 = authpriv) or filter by `_COMM=sshd`, `_COMM=sudo`, `_COMM=login`

### macOS
- No `auth.log`. Query the unified logging system via the `log` CLI:
  ```
  log show --style syslog --last 10m --predicate \
    'process == "sshd" OR process == "sudo" OR process == "loginwindow" \
     OR eventMessage CONTAINS[c] "authenticat"'
  ```
- Keep `--last` window small — `log show` is slow over long ranges
- Pass the predicate as a single argv element; **do not use `shell=True`**

### Windows
- No syslog at all. Read the **Security** event log via `pywin32` → `win32evtlog`

  | Event ID | Meaning | Label |
  |---|---|---|
  | 4624 | Successful logon | `OK` |
  | 4625 | Failed logon | `FAIL` |
  | 4672 | Special/elevated privileges | `PRIV` |
  | 4634 / 4647 | Logoff | `INFO` |
  | 4720 | User account created | `INFO` |

- Reading the Security log requires **Administrator**
- Detect admin with `ctypes.windll.shell32.IsUserAnAdmin()`
- Import `win32evtlog` **lazily** inside `WindowsAuthReader` so the module still loads on Linux/macOS

---

## Elevation requirements

| OS | What needs elevation | How |
|---|---|---|
| Linux | Auth panel (`adm` group); some network ownership detail | `sudo usermod -aG adm "$USER"` or run with `sudo` |
| macOS | `psutil.net_connections()` raises `AccessDenied` without root; some `log` predicates too | `sudo python sentinelai.py` |
| Windows | Security event log | Run terminal **as Administrator**. Use **Windows Terminal**, not legacy `cmd.exe` |

---

## Architecture — scaffold section map

The scaffold (`files/sentinelai.py`) is organized into five sections you implement in order:

### Section 1 — Filesystem watcher (cross-platform, via watchdog)

```python
class FSHandler(FileSystemEventHandler):
    def __init__(self, sink):          # store the shared deque
    def _record(self, action, path):   # append (timestamp, action, path) to sink
    def on_created(self, event):       # action "CREATE" (skip directories)
    def on_modified(self, event):      # action "MODIFY" (skip directories)
    def on_deleted(self, event):       # action "DELETE"
    def on_moved(self, event):         # action "MOVE", path = "src -> dest"
```

`watchdog` picks inotify / FSEvents / ReadDirectoryChangesW automatically. `deque.append` is atomic in CPython — safe to push from the background thread and drain from the UI thread.

### Section 2 — Auth readers (the platform-specific part)

Contract: every reader exposes `.available() -> bool` and `.read(n) -> list[tuple[str,str]]` where each tuple is `(label, text)` with label in `{OK, FAIL, SUDO, PRIV, INFO}`.

```python
class AuthReader:             # base interface
class LinuxAuthReader(AuthReader):    # file → journalctl fallback
class MacAuthReader(AuthReader):      # shells out to `log show`
class WindowsAuthReader(AuthReader):  # win32evtlog, lazy import

def classify_line(line: str) -> str:  # shared helper for text-based readers
def make_auth_reader() -> AuthReader: # factory — reads platform.system()
```

**`classify_line` logic:**
- `"FAIL"` — "failed password" / "authentication failure" / "invalid user"
- `"OK"` — "accepted" / "session opened"
- `"SUDO"` — "sudo"
- `"INFO"` — everything else

### Section 3 — Cross-platform helpers

```python
def is_admin() -> bool:
    # POSIX: os.geteuid() == 0
    # Windows: ctypes.windll.shell32.IsUserAnAdmin()
```

### Section 4 — Textual dashboard (`SentinelAI(App)`)

```
compose()        → Header + 2×2 Grid (4 panels) + status Static + Footer
on_mount()       → build DataTable columns, start Observer, prime CPU counters, set_interval
refresh_all()    → calls all five _refresh_* methods
_refresh_processes()  → psutil.process_iter, diff PIDs, sort new-first then by CPU, top 14
_refresh_network()    → psutil.net_connections(kind="inet"), guard AccessDenied, top 14
_refresh_auth()       → auth_reader.read(12), or hint row if not available()
_refresh_fs()         → drain last 14 from deque, newest first
_refresh_status()     → one-line summary: watch dir, auth status, interval, key hints
on_unmount()          → observer.stop() + .join(timeout=2)
```

**DataTable column schemas:**

| Table ID | Columns |
|---|---|
| `#proc` | Time, PID, User, CPU%, MEM%, Name |
| `#net` | Proto, Local, Remote, Status, PID, Process |
| `#auth` | Type, Event |
| `#fs` | Time, Action, Path |

### Section 5 — CLI entrypoint

```python
def main():
    # argparse: -w/--watch (default: Path.home()), -i/--interval float (default: 2.0)
    # SentinelAI(watch_dir=..., interval=...).run()
```

---

## Implementation order (keep it running at every step)

1. **CLI + empty Textual shell** — Section 5 + Section 4 layout → it runs, shows empty panels
2. **PROCESSES panel** — easiest, pure psutil
3. **FILESYSTEM panel** — watchdog handler + observer wiring
4. **NETWORK panel** — psutil, handle `AccessDenied` on macOS/Windows
5. **AUTH panel** — `LinuxAuthReader` first, then `MacAuthReader`, then `WindowsAuthReader`

---

## Working Linux implementation — key details

The file `sentinelai/sentinelai/sentinelai.py` is a complete, working Linux-only version. Differences from the scaffold:

- AUTH is hardcoded: reads `/var/log/auth.log` or `/var/log/secure`, no cross-platform reader classes
- No `make_auth_reader()` factory, no `WindowsAuthReader`/`MacAuthReader`
- `_panel()` helper uses a private attribute trick to pass title/id through Textual's compose → mount lifecycle

CSS (copy this directly):
```
Screen { background: $surface; }
#grid { grid-size: 2 2; grid-gutter: 1; padding: 1; }
.panel { border: round $accent; height: 100%; }
.title { background: $accent; color: $text; text-style: bold; padding: 0 1; }
DataTable { height: 1fr; }
#status { dock: bottom; padding: 0 1; color: $text-muted; }
```

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
