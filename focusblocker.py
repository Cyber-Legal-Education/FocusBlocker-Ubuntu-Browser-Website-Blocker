#!/usr/bin/python3 -I
"""FocusBlocker for Ubuntu: hosts-file website blocking + browser process guard.

The GUI runs unprivileged. System changes are made only after a pkexec prompt,
and only by a root-owned installed copy of this script (never by whatever file
the GUI happens to be running from).

One-time setup (run from a terminal; this is the only step that trusts the file
you are holding, so review it first):

    sudo python3 focusblocker.py --install

Then launch the GUI normally:

    python3 focusblocker.py

To remove everything, including the installed copy and polkit policy:

    sudo python3 focusblocker.py --uninstall

This is a practical distraction blocker, not a tamper-proof kiosk/security policy.
"""

from __future__ import annotations

import os
import sys

# When running as root, never import from the directory the script sits in: a
# stray json.py/base64.py there would otherwise run as root. (Under the "-I"
# shebang this is already the case; this covers `pkexec python3 script.py`.)
if os.geteuid() == 0:
    _script_dirs = {"", os.path.dirname(os.path.abspath(__file__)),
                    os.path.dirname(os.path.realpath(__file__))}
    sys.path[:] = [p for p in sys.path if p not in _script_dirs]

import argparse
import contextlib
import errno
import fcntl
import ipaddress
import json
import re
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

__version__ = "2.0.0"

APP_NAME = "FocusBlocker"
HOSTS_FILE = Path("/etc/hosts")
HOSTS_BACKUP = Path("/etc/hosts.focusblocker.original")
HOSTS_BEGIN = "# BEGIN FOCUSBLOCKER MANAGED BLOCK"
HOSTS_END = "# END FOCUSBLOCKER MANAGED BLOCK"
CONFIG_DIR = Path("/etc/focusblocker")
CONFIG_FILE = CONFIG_DIR / "config.json"
LIB_DIR = Path("/usr/local/lib/focusblocker")
INSTALLED_SCRIPT = LIB_DIR / "focusblocker.py"
UNIT_FILE = Path("/etc/systemd/system/focusblocker-browser-guard.service")
UNIT_NAME = "focusblocker-browser-guard.service"
POLICY_FILE = Path("/usr/share/polkit-1/actions/org.focusblocker.policy")
LOCK_FILE = Path("/run/focusblocker.lock")

MAX_DOMAINS = 10_000
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
GUARD_INTERVAL = 1.0        # seconds between process scans
KILL_GRACE_SECONDS = 5.0    # SIGTERM first; SIGKILL if still alive after this

# Optional and intentionally best-effort. Blocking some package hosts can affect
# non-browser products from the same vendor. These can be edited for local needs.
BROWSER_DOWNLOAD_DOMAINS = [
    "download.mozilla.org",
    "ftp.mozilla.org",
    "archive.mozilla.org",
    "dl.google.com",
    "edgedl.me.gvt1.com",
    "repo.vivaldi.com",
    "download.opera.com",
    "packages.microsoft.com",  # also used for other Microsoft Linux packages
]

# Exact executable / process names. Prefix matching was removed on purpose: it
# caught chrome_crashpad_handler (Electron apps, Brave), chromedriver,
# chromium-bsu, and similar non-browsers. New/renamed browsers may not match.
BROWSER_EXACT_NAMES = frozenset({
    "firefox", "firefox-esr", "firefox-bin", "firefox.real", "chromium",
    "chromium-browser", "chrome", "google-chrome", "google-chrome-stable",
    "msedge", "microsoft-edge", "microsoft-edge-stable", "opera", "vivaldi",
    "vivaldi-bin", "epiphany", "falkon", "konqueror", "tor-browser", "nyxt",
    "qutebrowser", "midori", "librewolf", "waterfox", "floorp", "zen",
    "zen-bin", "thorium-browser", "palemoon", "seamonkey",
    "ungoogled-chromium", "iridium", "iceweasel",
})
# The kernel truncates /proc/<pid>/comm to 15 characters, so also accept the
# truncated form of every long name.
_MATCH_NAMES = BROWSER_EXACT_NAMES | {n[:15] for n in BROWSER_EXACT_NAMES if len(n) > 15}

# Install directories of well-known browsers; any process whose executable lives
# under one of these (including helpers) counts as that browser.
BROWSER_EXE_DIRS = (
    "/usr/lib/firefox/", "/usr/lib/firefox-esr/", "/usr/lib64/firefox/",
    "/usr/lib/librewolf/", "/usr/lib/chromium/", "/usr/lib/chromium-browser/",
    "/opt/google/chrome/", "/opt/microsoft/msedge/", "/opt/vivaldi/",
    "/snap/firefox/", "/snap/chromium/",
    "/var/lib/snapd/snap/firefox/", "/var/lib/snapd/snap/chromium/",
)

# Common two-label public suffixes, so "bbc.co.uk" is treated as an apex domain.
MULTI_PART_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz",
    "net.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "co.kr", "or.kr", "co.in",
    "net.in", "org.in", "com.br", "net.br", "org.br", "com.cn", "net.cn",
    "org.cn", "com.mx", "com.ar", "com.tr", "com.tw", "com.hk", "com.sg",
    "com.my", "com.ph", "com.vn", "co.za", "co.il", "co.id", "com.ua",
})

DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

POLICY_XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1.0/policyconfig.dtd">
<policyconfig>
  <vendor>FocusBlocker</vendor>
  <action id="org.focusblocker.apply">
    <description>Change FocusBlocker system settings</description>
    <message>Authentication is required to change website and browser blocking rules</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">{INSTALLED_SCRIPT}</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>
</policyconfig>
"""


class FocusBlockerError(RuntimeError):
    """Raised for recoverable app/system errors."""


# --------------------------------------------------------------------------- #
# Domain handling
# --------------------------------------------------------------------------- #

def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _to_ascii_hostname(hostname: str) -> str:
    """Return the ASCII/punycode form of a hostname.

    ASCII input is passed through untouched (validated by DOMAIN_LABEL later).
    For non-ASCII input the optional ``idna`` package (IDNA 2008 + UTS46, same
    mapping as browsers) is preferred; the stdlib codec implements IDNA 2003
    and maps e.g. "ß" to "ss", which differs from what browsers resolve.
    """
    if hostname.isascii():
        return hostname
    try:
        import idna  # type: ignore[import-not-found]
    except ImportError:
        return hostname.encode("idna").decode("ascii")
    return idna.encode(hostname, uts46=True).decode("ascii")


def normalize_domain(value: str) -> str:
    """Accept a hostname or URL and return its lowercase ASCII hostname."""
    value = value.strip()
    if not value:
        raise ValueError("Enter a website hostname or URL.")
    if value.startswith("*."):
        raise ValueError("Wildcard domains are not supported by /etc/hosts. Add each hostname/subdomain separately.")
    candidate = value if "://" in value else "//" + value
    try:
        hostname = urlsplit(candidate).hostname
    except ValueError as exc:
        raise ValueError(f"Invalid hostname or URL: {value}") from exc
    if not hostname:
        raise ValueError(f"Could not read a hostname from: {value}")
    hostname = hostname.rstrip(".").lower()
    try:
        hostname = _to_ascii_hostname(hostname).lower()
    except UnicodeError as exc:
        raise ValueError(f"Invalid internationalized hostname: {value}") from exc
    if _is_ip_address(hostname):
        raise ValueError(f"'{hostname}' is an IP address; /etc/hosts can only block hostnames.")
    if len(hostname) > 253 or "." not in hostname:
        raise ValueError(f"'{hostname}' does not look like a fully qualified domain name.")
    labels = hostname.split(".")
    if any(not label or not DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError(f"Invalid hostname: {hostname}")
    if labels[-1].isdigit():
        raise ValueError(f"Invalid hostname (numeric top-level domain): {hostname}")
    if hostname in {"localhost", "localhost.localdomain"}:
        raise ValueError("Localhost entries cannot be blocked by this app.")
    return hostname


def parse_domain_lines(text: str) -> list[str]:
    """Parse the GUI text box: one hostname/URL per line, '#' starts a comment."""
    seen: dict[str, None] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        try:
            seen[normalize_domain(line)] = None
        except ValueError as exc:
            raise ValueError(f"Line {number}: {exc}") from exc
    return sorted(seen)


def _is_apex_domain(domain: str) -> bool:
    labels = domain.split(".")
    suffix_len = 2 if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES else 1
    return len(labels) == suffix_len + 1


def expand_domain_hosts(domains: list[str]) -> list[str]:
    """Normalize domain inputs and add www for apex domains only."""
    result: set[str] = set()
    for raw in domains:
        domain = normalize_domain(raw)
        result.add(domain)
        # Only add www automatically for registrable (apex) domains such as
        # example.com or example.co.uk, never for a supplied subdomain.
        if _is_apex_domain(domain) and not domain.startswith("www."):
            result.add("www." + domain)
    return sorted(result)


# --------------------------------------------------------------------------- #
# Browser process matching
# --------------------------------------------------------------------------- #

def is_browser_name(name: str) -> bool:
    """True when a process/executable *name* exactly matches a known browser."""
    base = os.path.basename(name.strip()).lower()
    if base.endswith(" (deleted)"):
        base = base[:-len(" (deleted)")]
    return base in _MATCH_NAMES


def is_browser_exe(path: str) -> bool:
    """True when an executable path is a known browser binary or lives in a known browser install dir."""
    path = path.strip()
    if path.endswith(" (deleted)"):
        path = path[:-len(" (deleted)")]
    return is_browser_name(path) or path.startswith(BROWSER_EXE_DIRS)


def _read_small(path: str, limit: int = 256) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return os.read(fd, limit).decode("utf-8", "ignore").strip()
    finally:
        os.close(fd)


def _browser_process_name(pid_text: str) -> str | None:
    """Return the matched browser name for a PID, or None."""
    try:
        exe = os.readlink(f"/proc/{pid_text}/exe")
    except FileNotFoundError:
        return None  # kernel thread, zombie, or already exited
    except OSError:
        exe = ""     # e.g. EACCES: fall back to comm only
    if exe and is_browser_exe(exe):
        return os.path.basename(exe)
    # comm also catches interpreter-launched browsers (exe is python3, comm is the script name).
    try:
        comm = _read_small(f"/proc/{pid_text}/comm")
    except OSError:
        return None
    return comm if comm and is_browser_name(comm) else None


def _signal_process(pid: int, pid_text: str, sig: int) -> None:
    """Signal a browser PID without racing PID reuse (uses pidfd when available)."""
    pidfd = None
    if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
        try:
            pidfd = os.pidfd_open(pid)
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                return
            pidfd = None  # kernel without pidfd support: fall back to kill()
    try:
        if pidfd is not None:
            # With the pidfd held, a reused PID makes the send fail with ESRCH,
            # so re-verifying identity here is race-free.
            if _browser_process_name(pid_text) is None:
                return
            signal.pidfd_send_signal(pidfd, sig)
        else:
            os.kill(pid, sig)
    except OSError:
        pass
    finally:
        if pidfd is not None:
            os.close(pidfd)


def guard_pass(self_pid: int, tracked: dict[int, float], now: float,
               pids: Iterable[str] | None = None) -> None:
    """One scan: SIGTERM new browser processes, SIGKILL ones that outlive the grace period."""
    if pids is None:
        try:
            pids = [name for name in os.listdir("/proc") if name.isdigit()]
        except OSError:
            return
    seen: set[int] = set()
    for pid_text in pids:
        pid = int(pid_text)
        if pid <= 1 or pid == self_pid:
            continue
        name = _browser_process_name(pid_text)
        if name is None:
            continue
        seen.add(pid)
        first_seen = tracked.get(pid)
        if first_seen is None:
            tracked[pid] = now
            print(f"{APP_NAME}: terminating {name} (pid {pid})", flush=True)
            _signal_process(pid, pid_text, signal.SIGTERM)
        elif now - first_seen >= KILL_GRACE_SECONDS:
            _signal_process(pid, pid_text, signal.SIGKILL)
    for pid in [p for p in tracked if p not in seen]:
        del tracked[pid]


def _guard_config_enabled(prev_sig: tuple | None, prev_enabled: bool) -> tuple[bool, tuple | None]:
    """Re-read the config only when it changed on disk."""
    try:
        st = os.stat(CONFIG_FILE)
    except OSError:
        return False, None
    sig = (st.st_mtime_ns, st.st_ino, st.st_size)
    if sig == prev_sig:
        return prev_enabled, sig
    if st.st_uid != 0 or st.st_mode & 0o022:
        print(f"{APP_NAME}: ignoring {CONFIG_FILE}: must be root-owned and not group/world-writable",
              file=sys.stderr, flush=True)
        return False, sig
    try:
        config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, sig
    return isinstance(config, dict) and config.get("block_browsers") is True, sig


def browser_guard_loop() -> int:
    """System service main loop. Repeatedly terminate detected browser processes."""
    _require_trusted_install()
    me = os.getpid()
    tracked: dict[int, float] = {}
    sig: tuple | None = None
    enabled = False
    while True:
        enabled, sig = _guard_config_enabled(sig, enabled)
        if enabled:
            guard_pass(me, tracked, time.monotonic())
        else:
            tracked.clear()
        time.sleep(GUARD_INTERVAL)


# --------------------------------------------------------------------------- #
# /etc/hosts rendering (pure functions)
# --------------------------------------------------------------------------- #

def has_managed_hosts_block(text: str) -> bool:
    return any(line.strip() in (HOSTS_BEGIN, HOSTS_END) for line in text.split("\n"))


def strip_managed_hosts_block(text: str) -> str:
    """Remove this app's managed block, leaving every other byte (incl. CRLF) intact."""
    lines = text.split("\n")
    starts = [i for i, line in enumerate(lines) if line.strip() == HOSTS_BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == HOSTS_END]
    if not starts and not ends:
        return text
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise FocusBlockerError(
            f"The FocusBlocker section in {HOSTS_FILE} is malformed (missing, duplicated or reversed "
            f"markers). Fix it by hand: delete the lines between and including the '{HOSTS_BEGIN}' / "
            f"'{HOSTS_END}' markers, or restore {HOSTS_BACKUP} if you have no other edits to keep.")
    del lines[starts[0]:ends[0] + 1]
    return "\n".join(lines)


def render_hosts(existing_text: str, domains: list[str]) -> str:
    """Render a hosts file preserving all text outside this app's managed section."""
    eol = "\r\n" if "\r\n" in existing_text else "\n"
    base = strip_managed_hosts_block(existing_text).rstrip("\r\n")
    hostnames = expand_domain_hosts(domains) if domains else []
    if not hostnames:
        return base + eol if base else ""
    section = [HOSTS_BEGIN]
    for host in hostnames:
        section.append(f"0.0.0.0 {host}")
        section.append(f":: {host}")
    section.append(HOSTS_END)
    block = eol.join(section) + eol
    return base + eol + eol + block if base else block


def _strict_bool(payload: dict[str, Any], key: str) -> bool:
    value = payload.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"'{key}' must be true or false.")
    return value


def validate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Invalid configuration data.")
    raw_domains = payload.get("domains", [])
    if not isinstance(raw_domains, list) or any(not isinstance(item, str) for item in raw_domains):
        raise ValueError("The domains list is invalid.")
    if len(raw_domains) > MAX_DOMAINS:
        raise ValueError(f"Too many domains ({len(raw_domains)}); the limit is {MAX_DOMAINS}.")
    return {
        "domains": sorted({normalize_domain(item) for item in raw_domains}),
        "block_browsers": _strict_bool(payload, "block_browsers"),
        "include_download_domains": _strict_bool(payload, "include_download_domains"),
    }


def blocked_domains_for_payload(config: dict[str, Any]) -> list[str]:
    """Domains in *config* are already normalized by validate_payload."""
    result = set(config["domains"])
    if config["include_download_domains"]:
        result.update(BROWSER_DOWNLOAD_DOMAINS)
    return sorted(result)


# --------------------------------------------------------------------------- #
# Privileged filesystem / service helpers
# --------------------------------------------------------------------------- #

def _require_root() -> None:
    if os.geteuid() != 0:
        raise FocusBlockerError("System changes require administrator permissions.")


def _installed_script_problem() -> str | None:
    """Describe why the installed copy can't be trusted, or None if it is fine."""
    try:
        file_st = os.lstat(INSTALLED_SCRIPT)
        dir_st = os.lstat(LIB_DIR)
    except FileNotFoundError:
        return "FocusBlocker is not installed system-wide yet."
    except OSError as exc:
        return f"Cannot inspect the installed FocusBlocker copy: {exc}."
    for label, st in (("script", file_st), ("directory", dir_st)):
        if stat.S_ISLNK(st.st_mode):
            return f"The installed FocusBlocker {label} must not be a symlink."
        if st.st_uid != 0 or st.st_mode & 0o022:
            return f"The installed FocusBlocker {label} must be owned by root and not writable by others."
    if not stat.S_ISREG(file_st.st_mode):
        return "The installed FocusBlocker script is not a regular file."
    return None


def _require_trusted_install() -> None:
    """Privileged actions only run from the root-owned installed copy."""
    _require_root()
    problem = _installed_script_problem()
    if problem:
        raise FocusBlockerError(f"{problem} Install it with: sudo python3 <path-to>/focusblocker.py --install")
    if os.path.realpath(__file__) != os.path.realpath(INSTALLED_SCRIPT):
        raise FocusBlockerError(
            f"Privileged actions only run from the installed copy ({INSTALLED_SCRIPT}), "
            f"not from {os.path.realpath(__file__)}.")


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_write(path: Path, content: str | bytes, mode: int = 0o644, uid: int = 0, gid: int = 0) -> None:
    """Write via temp file + fsync + rename, setting mode/owner before any data is written."""
    data = content.encode("utf-8", "surrogateescape") if isinstance(content, str) else content
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), mode)
            if os.geteuid() == 0:
                os.fchown(handle.fileno(), uid, gid)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise
    _fsync_dir(path.parent)


@contextlib.contextmanager
def _exclusive_lock(timeout: float = 30.0):
    """Serialize privileged operations (two GUIs, or us vs. a retry)."""
    fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise FocusBlockerError("Another FocusBlocker operation is in progress. Try again shortly.")
                time.sleep(0.2)
        yield
    finally:
        os.close(fd)  # closing the descriptor releases the lock


def _run_systemctl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    command = ["/usr/bin/systemctl", *args]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "systemctl failed").strip()
        raise FocusBlockerError(f"Command failed ({' '.join(command)}): {detail}")
    return result


def _hosts_target() -> Path:
    return Path(os.path.realpath(HOSTS_FILE))  # follow a symlinked /etc/hosts instead of replacing it


def _read_hosts() -> str:
    try:
        return _hosts_target().read_bytes().decode("utf-8", "surrogateescape")
    except FileNotFoundError:
        return ""


def _write_hosts(text: str) -> None:
    target = _hosts_target()
    try:
        st = target.stat()
        mode, uid, gid = stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid
    except FileNotFoundError:
        mode, uid, gid = 0o644, 0, 0
    _atomic_write(target, text, mode, uid, gid)


def _flush_dns() -> None:
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(["/usr/bin/resolvectl", "flush-caches"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False, timeout=15)


def _unit_text() -> str:
    return f"""[Unit]
Description=FocusBlocker browser process guard
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -I {INSTALLED_SCRIPT} --daemon
Restart=always
RestartSec=2
Nice=10
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
PrivateNetwork=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX
# CAP_SYS_PTRACE is required to read /proc/<pid>/exe of other users' processes.
CapabilityBoundingSet=CAP_KILL CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
"""


def _install_browser_service() -> None:
    _atomic_write(UNIT_FILE, _unit_text(), 0o644)
    _run_systemctl("daemon-reload")
    _run_systemctl("enable", UNIT_NAME)
    _run_systemctl("restart", UNIT_NAME)  # "enable --now" would keep an already-running old daemon


def _remove_browser_service() -> None:
    _run_systemctl("disable", "--now", UNIT_NAME, check=False)
    try:
        UNIT_FILE.unlink(missing_ok=True)
    finally:
        _run_systemctl("daemon-reload", check=False)
        _run_systemctl("reset-failed", UNIT_NAME, check=False)


def _ensure_lib_dir() -> None:
    if LIB_DIR.is_symlink():
        raise FocusBlockerError(f"{LIB_DIR} is a symlink; refusing to use it.")
    LIB_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(LIB_DIR, 0, 0)
    os.chmod(LIB_DIR, 0o755)


def _read_bytes_or_none(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def _rollback(original_hosts: str, previous_config: bytes | None, unit_existed: bool) -> None:
    """Best-effort restore after a failed apply."""
    with contextlib.suppress(Exception):
        _write_hosts(original_hosts)
    with contextlib.suppress(Exception):
        if previous_config is None:
            CONFIG_FILE.unlink(missing_ok=True)
        else:
            _atomic_write(CONFIG_FILE, previous_config, 0o644)
    if not unit_existed:
        with contextlib.suppress(Exception):
            _remove_browser_service()


# --------------------------------------------------------------------------- #
# Privileged entry points
# --------------------------------------------------------------------------- #

def apply_system_config(raw_payload: dict[str, Any]) -> str:
    """Apply host block list and optional browser guard. Must run as root."""
    _require_root()
    config = validate_payload(raw_payload)
    all_domains = blocked_domains_for_payload(config)

    with _exclusive_lock():
        original_hosts = _read_hosts()
        updated_hosts = render_hosts(original_hosts, all_domains)  # raises on a malformed block, before any change

        # Keep a one-time copy of the pre-FocusBlocker hosts file (never containing our block).
        if all_domains and not HOSTS_BACKUP.exists():
            _atomic_write(HOSTS_BACKUP, strip_managed_hosts_block(original_hosts), 0o600)

        previous_config = _read_bytes_or_none(CONFIG_FILE)
        unit_existed = UNIT_FILE.exists()
        try:
            if updated_hosts != original_hosts:
                _write_hosts(updated_hosts)
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            os.chmod(CONFIG_DIR, 0o755)
            _atomic_write(CONFIG_FILE, json.dumps(config, indent=2) + "\n", 0o644)
            if config["block_browsers"]:
                _install_browser_service()
                browser_msg = "Browser guard enabled (common browsers are terminated by a root-owned service)."
            else:
                _remove_browser_service()
                browser_msg = "Browser guard disabled."
        except Exception as exc:
            _rollback(original_hosts, previous_config, unit_existed)
            raise FocusBlockerError(f"Applying settings failed and was rolled back: {exc}") from exc

    _flush_dns()
    return f"Applied {len(all_domains)} hostname(s). {browser_msg}"


def remove_all_system_rules() -> str:
    """Remove FocusBlocker-managed hosts entries and its browser guard service."""
    _require_root()
    with _exclusive_lock():
        existing = _read_hosts()
        if has_managed_hosts_block(existing):
            _write_hosts(render_hosts(existing, []))
        _remove_browser_service()
        with contextlib.suppress(OSError):
            CONFIG_FILE.unlink(missing_ok=True)
            if CONFIG_DIR.exists() and not any(CONFIG_DIR.iterdir()):
                CONFIG_DIR.rmdir()
    _flush_dns()
    return (f"FocusBlocker-managed host entries and browser guard were removed. "
            f"The backup {HOSTS_BACKUP} was kept.")


def install_system() -> str:
    """Install this script as the root-owned copy that pkexec/systemd will run. Run via sudo."""
    _require_root()
    source = Path(os.path.realpath(__file__))
    _ensure_lib_dir()
    if source != Path(os.path.realpath(INSTALLED_SCRIPT)):
        if source.stat().st_mode & 0o002:
            raise FocusBlockerError(f"Refusing to install a world-writable script: {source}")
        _atomic_write(INSTALLED_SCRIPT, source.read_bytes(), 0o755)
    _atomic_write(POLICY_FILE, POLICY_XML, 0o644)
    _run_systemctl("try-restart", UNIT_NAME, check=False)
    return (f"Installed {INSTALLED_SCRIPT} and the polkit policy. "
            f"You can now run the GUI as your normal user: python3 {source}")


def uninstall_system() -> str:
    """Remove rules, service, installed copy and polkit policy (keeps the hosts backup)."""
    _require_root()
    message = remove_all_system_rules()
    for path in (INSTALLED_SCRIPT, POLICY_FILE):
        path.unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        LIB_DIR.rmdir()
    return message + " The installed script and polkit policy were removed."


# --------------------------------------------------------------------------- #
# GUI (runs unprivileged)
# --------------------------------------------------------------------------- #

def _load_existing_config() -> dict[str, Any] | None:
    try:
        return validate_payload(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None


def _run_privileged(args: list[str], payload: str | None = None, timeout: float = 300.0) -> tuple[int, str, str]:
    pkexec = "/usr/bin/pkexec" if os.access("/usr/bin/pkexec", os.X_OK) else (shutil.which("pkexec") or "pkexec")
    stdin_args: dict[str, Any] = {"input": payload} if payload is not None else {"stdin": subprocess.DEVNULL}
    result = subprocess.run([pkexec, str(INSTALLED_SCRIPT), *args], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, **stdin_args)
    return result.returncode, (result.stdout or "").strip(), (result.stderr or "").strip()


def _describe_failure(code: int, out: str, err: str) -> str:
    if code == 126 and not (out or err):
        return "Authentication was cancelled."
    if code == 127 and not (out or err):
        return "Not authorized, or no polkit authentication agent is running."
    return err or out or f"pkexec exited with code {code}."


def launch_gui() -> int:
    if os.geteuid() == 0:
        print(f"{APP_NAME}: run the GUI as your normal user, not as root.", file=sys.stderr)
        return 2
    try:
        import queue
        import threading
        import tkinter as tk
        from tkinter import messagebox, scrolledtext
    except ImportError:
        print("Tkinter is not installed. Run: sudo apt install python3-tk", file=sys.stderr)
        return 2

    problem = _installed_script_problem()
    existing = _load_existing_config()

    root = tk.Tk()
    root.title(f"FocusBlocker for Ubuntu {__version__}")
    root.geometry("720x680")
    root.minsize(620, 600)

    frame = tk.Frame(root, padx=18, pady=16)
    frame.pack(fill="both", expand=True)

    tk.Label(frame, text="FocusBlocker", font=("TkDefaultFont", 18, "bold")).pack(anchor="w")
    tk.Label(frame, text="Manage local hostname blocks and a system-wide browser process guard.",
             wraplength=670, justify="left").pack(anchor="w", pady=(4, 12))

    if problem:
        banner = tk.Frame(frame)
        banner.pack(fill="x", pady=(0, 10))
        tk.Label(banner, text=f"{problem} Run this in a terminal, then reopen the app:",
                 fg="#a11", wraplength=670, justify="left").pack(anchor="w")
        command = f"sudo python3 {shlex.quote(os.path.realpath(__file__))} --install"
        entry = tk.Entry(banner)
        entry.insert(0, command)
        entry.configure(state="readonly")
        entry.pack(fill="x", pady=(4, 0))

    tk.Label(frame, text="Websites to block (one hostname or URL per line, '#' for comments):",
             font=("TkDefaultFont", 10, "bold")).pack(anchor="w")
    domains_box = scrolledtext.ScrolledText(frame, height=12, wrap="word", undo=True)
    domains_box.pack(fill="both", expand=True, pady=(4, 10))
    if existing:
        domains_box.insert("1.0", "\n".join(existing["domains"]) + ("\n" if existing["domains"] else ""))

    browser_var = tk.BooleanVar(value=bool(existing and existing["block_browsers"]))
    downloads_var = tk.BooleanVar(value=bool(existing and existing["include_download_domains"]))
    tk.Checkbutton(frame, text="Block common browser processes (Brave is not affected)",
                   variable=browser_var).pack(anchor="w", pady=2)
    tk.Checkbutton(frame, text="Also block common browser download/package endpoints (best effort; may affect other software)",
                   variable=downloads_var, wraplength=670, justify="left").pack(anchor="w", pady=2)

    note = ("Important: /etc/hosts blocks exact hostnames, not wildcard subdomains. Add subdomains separately. "
            "This does not stop a determined administrator or guarantee blocking renamed/portable browsers, VPNs, "
            "DNS-over-HTTPS, or alternate download mirrors.")
    tk.Label(frame, text=note, fg="#8a4b08", wraplength=670, justify="left").pack(anchor="w", pady=(10, 6))

    status_var = tk.StringVar(value="")
    tk.Label(frame, textvariable=status_var, fg="#555").pack(anchor="w", pady=(0, 6))

    results: queue.Queue = queue.Queue()
    buttons = tk.Frame(frame)
    buttons.pack(fill="x", pady=(2, 0))

    def set_busy(busy: bool) -> None:
        state = "disabled" if (busy or problem) else "normal"
        apply_button.configure(state=state)
        remove_button.configure(state=state)
        status_var.set("Waiting for administrator authentication..." if busy else "")

    def run_async(title: str, args: list[str], payload: str | None) -> None:
        set_busy(True)

        def worker() -> None:
            try:
                code, out, err = _run_privileged(args, payload)
            except FileNotFoundError:
                code, out, err = -1, "", "pkexec not found. Install it with: sudo apt install policykit-1"
            except subprocess.TimeoutExpired:
                code, out, err = -1, "", ("Timed out waiting for the system change. It may or may not have been "
                                          "applied; reopen the app to check.")
            except OSError as exc:
                code, out, err = -1, "", str(exc)
            results.put((title, code, out, err))

        threading.Thread(target=worker, daemon=True).start()
        root.after(100, poll)

    def poll() -> None:
        try:
            title, code, out, err = results.get_nowait()
        except queue.Empty:
            root.after(100, poll)
            return
        set_busy(False)
        if code == 0:
            messagebox.showinfo(title, out or "Done.", parent=root)
        else:
            messagebox.showerror(f"{title} failed", _describe_failure(code, out, err), parent=root)

    def apply_clicked() -> None:
        try:
            domains = parse_domain_lines(domains_box.get("1.0", "end"))
        except ValueError as exc:
            messagebox.showerror("Invalid website", str(exc), parent=root)
            return
        if len(domains) > MAX_DOMAINS:
            messagebox.showerror("Too many websites", f"The limit is {MAX_DOMAINS} hostnames.", parent=root)
            return
        config = {"domains": domains, "block_browsers": bool(browser_var.get()),
                  "include_download_domains": bool(downloads_var.get())}
        if not messagebox.askyesno(
            "Apply system-wide changes?",
            "This will edit /etc/hosts and may enable a root-owned systemd service. "
            "Ubuntu will ask for administrator authentication. Continue?",
            parent=root,
        ):
            return
        run_async("Applied", ["--apply-system"], json.dumps(config))

    def remove_clicked() -> None:
        if not messagebox.askyesno(
            "Remove FocusBlocker rules?",
            "Remove this app's /etc/hosts entries and disable its browser guard? "
            "Other /etc/hosts entries will be preserved.",
            parent=root,
        ):
            return
        run_async("Removed", ["--remove-system"], None)

    apply_button = tk.Button(buttons, text="Apply system-wide", command=apply_clicked, padx=12, pady=6)
    apply_button.pack(side="left")
    remove_button = tk.Button(buttons, text="Remove all FocusBlocker rules", command=remove_clicked, padx=12, pady=6)
    remove_button.pack(side="right")
    set_busy(False)

    root.mainloop()
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _read_payload_from_stdin() -> dict[str, Any]:
    data = sys.stdin.buffer.read(MAX_PAYLOAD_BYTES + 1)
    if len(data) > MAX_PAYLOAD_BYTES:
        raise FocusBlockerError("The configuration supplied by the GUI is too large.")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise FocusBlockerError("Could not decode configuration supplied by the GUI.") from exc
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ubuntu local website and browser blocker")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--install", action="store_true",
                       help="install the root-owned copy and polkit policy (run with sudo)")
    group.add_argument("--uninstall", action="store_true",
                       help="remove all rules, the service, the installed copy and the policy (run with sudo)")
    group.add_argument("--apply-system", action="store_true", help=argparse.SUPPRESS)   # JSON on stdin
    group.add_argument("--remove-system", action="store_true", help=argparse.SUPPRESS)
    group.add_argument("--daemon", action="store_true", help=argparse.SUPPRESS)
    group.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    args = parser.parse_args(argv)

    try:
        if args.install:
            print(install_system())
            return 0
        if args.uninstall:
            print(uninstall_system())
            return 0
        if args.apply_system:
            _require_trusted_install()
            print(apply_system_config(_read_payload_from_stdin()))
            return 0
        if args.remove_system:
            _require_trusted_install()
            print(remove_all_system_rules())
            return 0
        if args.daemon:
            return browser_guard_loop()
        return launch_gui()
    except (FocusBlockerError, ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"{APP_NAME}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())