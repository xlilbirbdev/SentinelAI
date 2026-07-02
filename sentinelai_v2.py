#!/usr/bin/env python3
"""
SentinelAI - a host-based security monitoring tool.

Real-time terminal dashboard with three panels:
  - PROCESSES   newly spawned + top resource users
  - AUTH        recent login / sudo / privilege events (platform-specific)
  - FILESYSTEM  create / modify / delete / move events in a watched dir

psutil and watchdog are cross-platform, so PROCESSES and FILESYSTEM need no
per-OS code. AUTH is the one panel that differs per OS, so it's isolated
behind the AuthReader strategy interface below:

    class AuthReader:
        def available(self) -> bool
        def read(self, n=12) -> list[(label, text)]

  label is one of OK / FAIL / SUDO / PRIV / INFO. Readers never raise -
  read() returns [] on any failure, and the UI shows a hint when
  available() is False.

Stack: Python, psutil, Textual, watchdog (+ pywin32 on Windows).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections import deque
from datetime import datetime
from pathlib import Path
import argparse

import psutil
from textual.app import App, ComposeResult
from textual.containers import Grid, Vertical
from textual.widgets import Header, Footer, DataTable, Static
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FSHandler(FileSystemEventHandler):
    def __init__(self, sink: deque):
        super().__init__()
        self.sink = sink

    def _record(self, action: str, path: str):
        self.sink.append((datetime.now().strftime("%H:%M:%S"), action, path))

    def on_created(self, event):
        if not event.is_directory:
            self._record("CREATE", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._record("MODIFY", event.src_path)

    def on_deleted(self, event):
        self._record("DELETE", event.src_path)

    def on_moved(self, event):
        self._record("MOVE", f"{event.src_path} -> {event.dest_path}")


class AuthReader:
    """Base interface. Every subclass must degrade to [] / False, never raise."""

    def available(self) -> bool:
        raise NotImplementedError

    def read(self, n: int = 12) -> list[tuple[str, str]]:
        raise NotImplementedError


def classify_line(line: str) -> str:
    """Shared label heuristic for the text-based readers (Linux, macOS)."""
    low = line.lower()
    if "failed password" in low or "authentication failure" in low or "invalid user" in low:
        return "FAIL"
    if "accepted" in low or "session opened" in low:
        return "OK"
    if "sudo" in low:
        return "SUDO"
    return "INFO"


class LinuxAuthReader(AuthReader):
    """Tails /var/log/auth.log or /var/log/secure; falls back to journalctl
    on systemd distros that ship no plain file."""

    CANDIDATE_PATHS = ("/var/log/auth.log", "/var/log/secure")
    KEYWORDS = (
        "sshd", "sudo", "su:", "login", "authentication failure",
        "failed password", "accepted", "session opened", "session closed",
        "invalid user",
    )

    def __init__(self):
        self._path = next(
            (p for p in self.CANDIDATE_PATHS if os.path.exists(p) and os.access(p, os.R_OK)),
            None,
        )
        self._journalctl = shutil.which("journalctl")

    def available(self) -> bool:
        return self._path is not None or self._journalctl is not None

    def read(self, n: int = 12) -> list[tuple[str, str]]:
        lines = self._read_file(n) if self._path else self._read_journal(n)
        return [self._classify(line) for line in lines]

    def _read_file(self, n: int) -> list[str]:
        try:
            with open(self._path, "r", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return []
        hits = [ln.rstrip() for ln in lines if any(k in ln.lower() for k in self.KEYWORDS)]
        return hits[-n:]

    def _read_journal(self, n: int) -> list[str]:
        if not self._journalctl:
            return []
        try:
            proc = subprocess.run(
                ["journalctl", "--no-pager", "-n", str(n), "SYSLOG_FACILITY=10"],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return []
        return [ln for ln in proc.stdout.splitlines() if ln.strip()][-n:]

    @staticmethod
    def _classify(line: str) -> tuple[str, str]:
        parts = line.split(None, 4)
        text = parts[4] if len(parts) >= 5 else line
        return classify_line(line), text[:90]


class MacAuthReader(AuthReader):
    """Shells out to `log show` against the unified log - macOS has no auth.log."""

    PREDICATE = (
        'process == "sshd" OR process == "sudo" OR process == "loginwindow" '
        'OR eventMessage CONTAINS[c] "authenticat"'
    )

    def __init__(self):
        self._log_bin = shutil.which("log")

    def available(self) -> bool:
        return self._log_bin is not None

    def read(self, n: int = 12) -> list[tuple[str, str]]:
        if not self._log_bin:
            return []
        try:
            proc = subprocess.run(
                [self._log_bin, "show", "--style", "syslog", "--last", "10m",
                 "--predicate", self.PREDICATE],
                capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            return []
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        return [(classify_line(ln), ln[-90:]) for ln in lines[-n:]]


class WindowsAuthReader(AuthReader):
    """Reads the Security event log via pywin32. Requires Administrator.
    win32evtlog is imported lazily so this module still loads on non-Windows
    machines without pywin32 installed."""

    EVENT_LABELS = {4624: "OK", 4625: "FAIL", 4672: "PRIV", 4634: "INFO", 4647: "INFO"}

    def __init__(self):
        try:
            import win32evtlog
            self._win32evtlog = win32evtlog
        except ImportError:
            self._win32evtlog = None

    def available(self) -> bool:
        return self._win32evtlog is not None and is_admin()

    def read(self, n: int = 12) -> list[tuple[str, str]]:
        if not self.available():
            return []
        win32evtlog = self._win32evtlog
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events: list[tuple[str, str]] = []
        handle = None
        try:
            handle = win32evtlog.OpenEventLog(None, "Security")
            while len(events) < n:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                for rec in records:
                    label = self.EVENT_LABELS.get(rec.EventID & 0xFFFF)
                    if not label:
                        continue
                    user = rec.StringInserts[5] if rec.StringInserts and len(rec.StringInserts) > 5 else "?"
                    when = rec.TimeGenerated.strftime("%H:%M:%S")
                    events.append((label, f"{when} EventID {rec.EventID & 0xFFFF} user={user}"))
                    if len(events) >= n:
                        break
        except Exception:
            return []
        finally:
            if handle is not None:
                win32evtlog.CloseEventLog(handle)
        return list(reversed(events))


class _NullAuthReader(AuthReader):
    """Fallback for an unrecognized OS - keeps the UI degrading gracefully."""

    def available(self) -> bool:
        return False

    def read(self, n: int = 12) -> list[tuple[str, str]]:
        return []


def make_auth_reader() -> AuthReader:
    """Factory: pick the right reader for this OS."""
    import platform

    system = platform.system()
    if system == "Linux":
        return LinuxAuthReader()
    if system == "Darwin":
        return MacAuthReader()
    if system == "Windows":
        return WindowsAuthReader()
    return _NullAuthReader()


def is_admin() -> bool:
    """Used only to drive 'run as admin/sudo for full visibility' hints."""
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class SentinelAI(App):
    CSS = """
    Screen { background: $surface; }
    #grid {
        grid-size: 2 2;
        grid-gutter: 1;
        padding: 1;
    }
    .panel { border: round $accent; height: 100%; }
    .title { background: $accent; color: $text; text-style: bold; padding: 0 1; }
    DataTable { height: 1fr; }
    #panel_fs { column-span: 2; }
    #status { dock: bottom; padding: 0 1; color: $text-muted; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh_now", "Refresh"),
    ]

    def __init__(self, watch_dir: str, interval: float = 2.0):
        super().__init__()
        self.watch_dir = os.path.abspath(os.path.expanduser(watch_dir))
        self.interval = interval
        self._seen_pids: set[int] = set(psutil.pids())
        self._fs_events: deque = deque(maxlen=200)
        self._auth = make_auth_reader()
        self._observer: Observer | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Grid(id="grid"):
            yield self._panel("proc", "PROCESSES  (top CPU / newly spawned)",
                               ("Time", "PID", "User", "CPU%", "MEM%", "Name"))
            yield self._panel("auth", "AUTH / LOGIN EVENTS", ("Type", "Event"))
            yield self._panel("fs", f"FILESYSTEM  ({self.watch_dir})",
                               ("Time", "Action", "Path"), panel_id="panel_fs")
        yield Static("", id="status")
        yield Footer()

    @staticmethod
    def _panel(table_id: str, title: str, columns: tuple[str, ...],
               panel_id: str | None = None) -> Vertical:
        table = DataTable(id=table_id, zebra_stripes=True, cursor_type="none")
        table.add_columns(*columns)
        return Vertical(Static(title, classes="title"), table, id=panel_id, classes="panel")

    def on_mount(self) -> None:
        try:
            self._observer = Observer()
            self._observer.schedule(FSHandler(self._fs_events), self.watch_dir, recursive=True)
            self._observer.start()
        except Exception as exc:
            self._fs_events.append((datetime.now().strftime("%H:%M:%S"), "ERROR", f"watch failed: {exc}"))

        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        self.set_interval(self.interval, self.refresh_all)
        self.refresh_all()

    def action_refresh_now(self) -> None:
        self.refresh_all()

    def refresh_all(self) -> None:
        self._refresh_processes()
        self._refresh_auth()
        self._refresh_fs()
        self._refresh_status()

    def _refresh_processes(self) -> None:
        table = self.query_one("#proc", DataTable)
        table.clear()
        current = set(psutil.pids())
        new_pids = current - self._seen_pids
        self._seen_pids = current

        rows = []
        for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
            try:
                info = p.info
                rows.append((
                    info["pid"], info.get("name") or "?",
                    (info.get("username") or "?")[:12],
                    info.get("cpu_percent") or 0.0,
                    info.get("memory_percent") or 0.0,
                    info["pid"] in new_pids,
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        rows.sort(key=lambda r: (not r[5], -r[3]))
        now = datetime.now().strftime("%H:%M:%S")
        for pid, name, user, cpu, mem, is_new in rows[:14]:
            label = ("NEW " if is_new else "") + name
            table.add_row(now, str(pid), user, f"{cpu:.1f}", f"{mem:.1f}", label)

    def _refresh_auth(self) -> None:
        table = self.query_one("#auth", DataTable)
        table.clear()
        if not self._auth.available():
            table.add_row("INFO", self._auth_hint())
            return
        for label, text in self._auth.read(n=12):
            table.add_row(label, text[:90])

    def _auth_hint(self) -> str:
        import platform
        system = platform.system()
        if system == "Linux":
            return "No readable auth log. Add user to 'adm' group or run with sudo."
        if system == "Darwin":
            return "Run with sudo for full 'log show' access."
        if system == "Windows":
            return "Run this terminal as Administrator to read the Security log."
        return "Auth events are not supported on this OS."

    def _refresh_fs(self) -> None:
        table = self.query_one("#fs", DataTable)
        table.clear()
        recent = list(self._fs_events)[-14:]
        for ts, action, path in reversed(recent):
            short = path if len(path) <= 60 else "..." + path[-57:]
            table.add_row(ts, action, short)

    def _refresh_status(self) -> None:
        auth = "available" if self._auth.available() else "unavailable"
        msg = (f"watching {self.watch_dir}  |  auth: {auth}  |  "
               f"interval {self.interval:.0f}s  |  press q to quit, r to refresh")
        self.query_one("#status", Static).update(msg)

    def on_unmount(self) -> None:
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=2)


def main():
    ap = argparse.ArgumentParser(description="SentinelAI host monitor (no network panel)")
    ap.add_argument("-w", "--watch", default=str(Path.home()),
                     help="directory to watch for filesystem changes (default: home)")
    ap.add_argument("-i", "--interval", type=float, default=2.0,
                     help="refresh interval in seconds (default: 2)")
    args = ap.parse_args()
    SentinelAI(watch_dir=args.watch, interval=args.interval).run()


if __name__ == "__main__":
    main()
