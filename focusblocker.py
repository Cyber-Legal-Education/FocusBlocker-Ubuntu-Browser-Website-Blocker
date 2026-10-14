#!/usr/bin/python3 -I
"""FocusBlocker for Ubuntu: hosts-file website blocking + browser process guard.

The GUI runs unprivileged. System changes are made only after a pkexec prompt,
and only by a root-owned installed copy of this script (never by whatever file
the GUI happens to be running from).

One-time setup (run from a terminal; this is the only step that trusts the file
you are holding, so review it first):

    sudo python3 focusblocker.py --install

Then launch the GUI normally, or from your application menu (--install adds a
"FocusBlocker" entry there):

    python3 focusblocker.py

To add your own menu entry and a desktop shortcut (run as your normal user):

    python3 focusblocker.py --install-launcher      # undo: --remove-launcher

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
import base64
import contextlib
import errno
import fcntl
import grp
import hashlib
import ipaddress
import json
import math
import pwd
import re
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time
import zlib
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

__version__ = "2.1.0"

APP_NAME = "FocusBlocker"
HOSTS_FILE = Path("/etc/hosts")
HOSTS_BACKUP = Path("/etc/hosts.focusblocker.original")
HOSTS_BEGIN = "# BEGIN FOCUSBLOCKER MANAGED BLOCK"
HOSTS_END = "# END FOCUSBLOCKER MANAGED BLOCK"
CONFIG_DIR = Path("/etc/focusblocker")
CONFIG_FILE = CONFIG_DIR / "config.json"
LIB_DIR = Path("/usr/lib/focusblocker")  # every parent is root-only on all distros
LEGACY_LIB_DIR = Path("/usr/local/lib/focusblocker")  # 2.0.x location; its parents can be group-writable
INSTALLED_SCRIPT = LIB_DIR / "focusblocker.py"
UNIT_FILE = Path("/etc/systemd/system/focusblocker-browser-guard.service")
UNIT_NAME = "focusblocker-browser-guard.service"
POLICY_FILE = Path("/usr/share/polkit-1/actions/org.focusblocker.policy")
LOCK_FILE = Path("/run/focusblocker.lock")
SYSTEM_DESKTOP_FILE = Path("/usr/share/applications/focusblocker.desktop")
SYSTEM_ICON_FILE = Path("/usr/share/icons/hicolor/256x256/apps/focusblocker.png")

MAX_DOMAINS = 10_000
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_ENTRY_LENGTH = 2048     # characters per domain/URL entry, checked before any URL/IDNA parsing
# Components at or above this path are not inspected by _untrusted_component (tests point it at a temp dir).
TRUST_ANCHOR = Path("/")
# Environment for root-side subprocesses: never inherit SYSTEMD_*/PATH/LD_* style variables.
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"}

# Hostnames the root side refuses to block, because doing so breaks package updates, time sync,
# connectivity checks or the machine's own name. A seatbelt against mistakes and against another
# process of yours raising the polkit prompt with a harmful list; not a security boundary
# (an administrator can still edit /etc/hosts by hand).
PROTECTED_HOSTS = frozenset({
    "archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com", "changelogs.ubuntu.com",
    "esm.ubuntu.com", "motd.ubuntu.com", "ntp.ubuntu.com", "keyserver.ubuntu.com",
    "connectivity-check.ubuntu.com", "api.snapcraft.io", "livepatch.canonical.com",
    "contracts.canonical.com", "deb.debian.org", "security.debian.org", "ftp.debian.org",
})
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
    if len(value) > MAX_ENTRY_LENGTH:
        raise ValueError(f"Entry is too long ({len(value)} characters; limit {MAX_ENTRY_LENGTH}). "
                         "Paste just the hostname.")
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


def _local_hostnames() -> set[str]:
    names: set[str] = set()
    with contextlib.suppress(OSError):
        names.add(socket.gethostname().strip().lower())
    with contextlib.suppress(OSError, UnicodeError):
        names.add(Path("/etc/hostname").read_text(encoding="utf-8").strip().lower())
    names.discard("")
    return names


def _protected_hosts() -> set[str]:
    return set(PROTECTED_HOSTS) | _local_hostnames()


def _check_not_protected(domain: str, protected: set[str]) -> None:
    if domain in protected:
        raise ValueError(
            f"'{domain}' is protected: blocking it could break system updates or this machine's own "
            f"networking. If you really need it, edit {HOSTS_FILE} by hand.")


def parse_domain_lines(text: str) -> list[str]:
    """Parse the GUI text box: one hostname/URL per line, '#' starts a comment."""
    seen: dict[str, None] = {}
    protected = _protected_hosts()
    for number, raw in enumerate(text.splitlines(), 1):
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line:
            continue
        try:
            domain = normalize_domain(line)
            _check_not_protected(domain, protected)
            seen[domain] = None
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
            pids = [name for name in os.listdir("/proc") if name.isascii() and name.isdecimal()]
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
    domains = sorted({normalize_domain(item) for item in raw_domains})
    protected = _protected_hosts()
    for domain in domains:
        _check_not_protected(domain, protected)
    return {
        "domains": domains,
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


def _group_is_private(gid: int, owner_uid: int) -> bool:
    """True if *gid* is a per-user private group that nobody but *owner_uid* belongs to.

    Ubuntu's default umask (002) makes files you create group-writable, so a group-write bit is
    harmless when the group contains only you.
    """
    try:
        owner = pwd.getpwuid(owner_uid).pw_name
        if set(grp.getgrgid(gid).gr_mem) - {owner}:
            return False
        return all(user.pw_uid == owner_uid for user in pwd.getpwall() if user.pw_gid == gid)
    except (KeyError, OSError):
        return False


def _untrusted_component(path: Path, allowed_uids: set[int], *, private_group_ok: bool = False,
                         sticky_ok: bool = False) -> str | None:
    """Return the first component of *path* (the file or any parent directory) that is owned by a
    uid outside *allowed_uids* or is writable by others; None if the whole chain is clean.

    The whole chain matters: whoever can write ANY parent directory can rename it away and put
    their own file in its place, so the file's own mode proves nothing.
    """
    real = Path(os.path.realpath(path))
    for component in (real, *real.parents):
        if component == TRUST_ANCHOR:
            break
        st = os.lstat(component)
        if st.st_uid not in allowed_uids:
            return str(component)
        sticky_dir = sticky_ok and stat.S_ISDIR(st.st_mode) and bool(st.st_mode & stat.S_ISVTX)
        if st.st_mode & 0o002 and not sticky_dir:
            return str(component)
        if (st.st_mode & 0o020 and not sticky_dir
                and not (private_group_ok and _group_is_private(st.st_gid, st.st_uid))):
            return str(component)
    return None


def _installed_script_problem() -> str | None:
    """Describe why the installed copy can't be trusted, or None if it is fine."""
    try:
        file_st = os.lstat(INSTALLED_SCRIPT)
    except FileNotFoundError:
        return "FocusBlocker is not installed system-wide yet."
    except OSError as exc:
        return f"Cannot inspect the installed FocusBlocker copy: {exc}."
    if stat.S_ISLNK(file_st.st_mode):
        return "The installed FocusBlocker script must not be a symlink."
    if not stat.S_ISREG(file_st.st_mode):
        return "The installed FocusBlocker script is not a regular file."
    if file_st.st_uid != 0 or file_st.st_mode & 0o022:
        return "The installed FocusBlocker script must be owned by root and not writable by others."
    if LIB_DIR.is_symlink():
        return "The installed FocusBlocker directory must not be a symlink."
    try:
        bad = _untrusted_component(LIB_DIR, {0})
    except OSError as exc:
        return f"Cannot inspect the installed FocusBlocker directory: {exc}."
    if bad:
        return (f"The installed FocusBlocker directory is not safe: {bad} must be owned by root "
                "and not writable by others.")
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
    fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
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
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=30, env=SAFE_ENV)
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
                       stderr=subprocess.DEVNULL, check=False, timeout=15, env=SAFE_ENV)


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
    """Create the install directory fresh, or reuse one that is already root-owned and locked down.

    A pre-existing directory that fails the check is refused, not adopted: chown/chmod would leave
    whatever its previous owner put inside.
    """
    if LIB_DIR.is_symlink():
        raise FocusBlockerError(f"{LIB_DIR} is a symlink; refusing to use it.")
    if LIB_DIR.exists():
        bad = _untrusted_component(LIB_DIR, {0})
        if bad:
            raise FocusBlockerError(f"{LIB_DIR} already exists but {bad} is not owned by root or is writable "
                                    "by others. Remove or repair it, then retry.")
        return
    LIB_DIR.mkdir(parents=True)
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
    return f"Applied {len(expand_domain_hosts(all_domains))} hostname(s). {browser_msg}"


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


def _remove_legacy_install() -> None:
    """Remove the 2.0.x layout (/usr/local/lib/focusblocker). Only the known file and an empty dir."""
    if LEGACY_LIB_DIR.is_symlink():
        return
    with contextlib.suppress(OSError):
        (LEGACY_LIB_DIR / "focusblocker.py").unlink(missing_ok=True)
        LEGACY_LIB_DIR.rmdir()


def install_system() -> str:
    """Install this script as the root-owned copy that pkexec/systemd will run. Run via sudo."""
    _require_root()
    source = Path(os.path.realpath(__file__))
    # One descriptor: the bytes we check, hash and install are the very same bytes.
    with open(source, "rb") as handle:
        source_stat = os.fstat(handle.fileno())
        data = handle.read()
    if source_stat.st_mode & 0o002:
        raise FocusBlockerError(f"Refusing to install a world-writable script: {source}")
    notes = []
    if source_stat.st_uid != 0:
        notes.append(f"Note: {source} is owned by uid {source_stat.st_uid}, so anything running as that user "
                     "could have modified it. Compare the hash above with the file you reviewed.")
    _ensure_lib_dir()
    if INSTALLED_SCRIPT.is_symlink():
        INSTALLED_SCRIPT.unlink()
    if source != Path(os.path.realpath(INSTALLED_SCRIPT)):
        _atomic_write(INSTALLED_SCRIPT, data, 0o755)
    _atomic_write(POLICY_FILE, POLICY_XML, 0o644)
    _atomic_write(SYSTEM_ICON_FILE, _icon_png(256), 0o644)
    _atomic_write(SYSTEM_DESKTOP_FILE, _desktop_entry(INSTALLED_SCRIPT, SYSTEM_ICON_FILE), 0o644)
    _remove_legacy_install()
    if UNIT_FILE.exists():  # an existing guard may still point at the old location
        _atomic_write(UNIT_FILE, _unit_text(), 0o644)
        _run_systemctl("daemon-reload", check=False)
    _run_systemctl("try-restart", UNIT_NAME, check=False)
    problem = _installed_script_problem()
    if problem:
        raise FocusBlockerError(f"Installed, but the result would be refused at run time: {problem}")
    message = (f"Installed {INSTALLED_SCRIPT}, the polkit policy and an application-menu entry "
               f"(search for \"FocusBlocker\"; log out and in if it doesn't appear yet). "
               f"SHA-256 of the installed script: {hashlib.sha256(data).hexdigest()}. "
               f"For a desktop shortcut, run as your normal user: python3 {source} --install-launcher")
    return " ".join([message, *notes])


def uninstall_system() -> str:
    """Remove rules, service, installed copy and polkit policy (keeps the hosts backup)."""
    _require_root()
    message = remove_all_system_rules()
    _remove_legacy_install()
    for path in (INSTALLED_SCRIPT, POLICY_FILE, SYSTEM_DESKTOP_FILE, SYSTEM_ICON_FILE):
        path.unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        LIB_DIR.rmdir()
    return message + " The installed script, polkit policy and menu entry were removed."


# --------------------------------------------------------------------------- #
# Icon and launchers
# --------------------------------------------------------------------------- #

def _icon_png(size: int = 256) -> bytes:
    """Render the app icon (a focus target with a block slash) as an RGBA PNG, no dependencies."""
    half = size / 2.0
    corner = 0.22 * size
    ring_r, ring_w = 0.30 * size, 0.075 * size
    dot_r = 0.10 * size
    slash_w = 0.060 * size
    slash_reach = ring_r + ring_w
    bg, white, teal, red = (0x24, 0x3B, 0x55), (255, 255, 255), (0x3E, 0xC1, 0xB3), (0xE5, 0x48, 0x4D)

    def cover(distance: float) -> float:  # signed distance (px) -> anti-aliased coverage 0..1
        return min(1.0, max(0.0, 0.5 - distance))

    def mix(base: tuple, top: tuple, alpha: float) -> tuple:
        return tuple(b + (t - b) * alpha for b, t in zip(base, top))

    raw = bytearray()
    for y in range(size):
        raw.append(0)  # PNG filter type 0
        py = y + 0.5 - half
        for x in range(size):
            px = x + 0.5 - half
            qx, qy = abs(px) - (half - corner), abs(py) - (half - corner)
            a_bg = cover(math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) - corner)
            r = math.hypot(px, py)
            colour = mix(bg, white, cover(abs(r - ring_r) - ring_w / 2))
            colour = mix(colour, teal, cover(r - dot_r))
            a_slash = cover(abs(px - py) / math.sqrt(2) - slash_w / 2) * cover(r - slash_reach)
            colour = mix(colour, red, a_slash)
            raw += bytes((round(colour[0]), round(colour[1]), round(colour[2]), round(255 * a_bg)))

    def chunk(kind: bytes, data: bytes) -> bytes:
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


def _desktop_exec_quote(path: str) -> str:
    """Quote a path for a .desktop Exec= line."""
    if any(ch in path for ch in '"`$\\\n'):
        raise FocusBlockerError(f"The path contains characters a .desktop file cannot hold safely: {path!r}. "
                                "Move the script to a simpler path and try again.")
    return '"' + path.replace("%", "%%") + '"'


def _desktop_entry(script: Path, icon: Path) -> str:
    if any(ch in str(icon) for ch in "\r\n"):
        raise FocusBlockerError(f"The icon path contains a line break: {str(icon)!r}")
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Version=1.0\n"
        "Name=FocusBlocker\n"
        "GenericName=Website and Browser Blocker\n"
        "Comment=Block distracting websites and browsers\n"
        f"Exec=/usr/bin/python3 -I {_desktop_exec_quote(str(script))}\n"
        f"Icon={icon}\n"
        "Terminal=false\n"
        "Categories=Utility;\n"
        "Keywords=focus;block;website;productivity;distraction;\n"
        "StartupNotify=true\n"
        "StartupWMClass=FocusBlocker\n"
    )


def _user_data_dir() -> Path:
    configured = os.environ.get("XDG_DATA_HOME", "")
    return Path(configured) if configured.startswith("/") else Path.home() / ".local" / "share"


def _desktop_dir() -> Path | None:
    """The user's Desktop folder, or None if there isn't a real one."""
    try:
        reported = subprocess.run(["xdg-user-dir", "DESKTOP"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        reported = ""
    for candidate in (reported, str(Path.home() / "Desktop")):
        path = Path(candidate) if candidate else None
        if path and path.is_dir() and path != Path.home():
            return path
    return None


def _user_launcher_paths() -> tuple[Path, Path]:
    data = _user_data_dir()
    return (data / "applications" / "focusblocker.desktop",
            data / "icons" / "hicolor" / "256x256" / "apps" / "focusblocker.png")


def install_launcher() -> str:
    """Add FocusBlocker to the user's application menu and put a shortcut on the desktop."""
    if os.geteuid() == 0:
        raise FocusBlockerError("Run this as your normal user (without sudo) so the shortcut lands in your account.")
    # Prefer the root-owned installed copy: it can't be tampered with by user-level processes.
    use_installed = _installed_script_problem() is None
    script = INSTALLED_SCRIPT if use_installed else Path(os.path.realpath(__file__))
    if not use_installed:
        # The shortcut will run this file as you, so nobody else may be able to change it.
        bad = _untrusted_component(script, {0, os.geteuid()}, private_group_ok=True, sticky_ok=True)
        if bad:
            raise FocusBlockerError(
                f"Refusing to create a launcher for {script}: {bad} is owned by another user or writable by "
                "other users, so they could change what the shortcut runs. Move the script into a folder only "
                "you control (for example ~/.local/share/focusblocker), or install it system-wide with: "
                f"sudo python3 {shlex.quote(str(script))} --install")
    app_file, icon_file = _user_launcher_paths()
    _atomic_write(icon_file, _icon_png(256), 0o644)
    entry = _desktop_entry(script, icon_file)
    _atomic_write(app_file, entry, 0o644)
    notes = [f"Added FocusBlocker to your application menu ({app_file})."]
    desktop = _desktop_dir()
    if desktop is None:
        notes.append("No Desktop folder was found, so no desktop shortcut was created.")
    else:
        shortcut = desktop / "FocusBlocker.desktop"
        _atomic_write(shortcut, entry, 0o755)
        gio = shutil.which("gio")
        if gio:  # lets GNOME launch it without the "Allow Launching" step
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                subprocess.run([gio, "set", str(shortcut), "metadata::trusted", "true"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
        notes.append(f"Placed a shortcut on your desktop ({shortcut}). If it shows a generic icon or a warning, "
                     "right-click it and choose 'Allow Launching'.")
    if script != INSTALLED_SCRIPT:
        notes.append(f"It launches {script}; run --install-launcher again if you move that file.")
    return " ".join(notes)


def remove_launcher() -> str:
    """Remove the per-user menu entry, icon and desktop shortcut."""
    if os.geteuid() == 0:
        raise FocusBlockerError("Run this as your normal user (without sudo).")
    app_file, icon_file = _user_launcher_paths()
    targets = [app_file, icon_file]
    desktop = _desktop_dir()
    if desktop is not None:
        targets.append(desktop / "FocusBlocker.desktop")
    removed = 0
    for path in targets:
        if path.exists():
            path.unlink()
            removed += 1
    return f"Removed {removed} launcher file(s)."


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

    root = tk.Tk(className="FocusBlocker")  # matches StartupWMClass in the .desktop file
    root.title(f"FocusBlocker for Ubuntu {__version__}")
    icon_image = small_icon = None
    try:
        icon_image = tk.PhotoImage(data=base64.b64encode(_icon_png(128)).decode("ascii"))
        root.iconphoto(True, icon_image)
        small_icon = icon_image.subsample(2, 2)
    except tk.TclError:
        icon_image = small_icon = None
    root.geometry("720x680")
    root.minsize(620, 600)

    frame = tk.Frame(root, padx=18, pady=16)
    frame.pack(fill="both", expand=True)

    header = tk.Frame(frame)
    header.pack(anchor="w")
    if small_icon is not None:
        tk.Label(header, image=small_icon).pack(side="left", padx=(0, 10))
    tk.Label(header, text="FocusBlocker", font=("TkDefaultFont", 18, "bold")).pack(side="left")
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

    def shortcut_clicked() -> None:
        try:
            messagebox.showinfo("Desktop shortcut", install_launcher(), parent=root)
        except (FocusBlockerError, OSError, ValueError, subprocess.SubprocessError) as exc:
            messagebox.showerror("Could not add shortcut", str(exc), parent=root)

    apply_button = tk.Button(buttons, text="Start blocking", command=apply_clicked, padx=14, pady=6,
                             font=("TkDefaultFont", 10, "bold"))
    apply_button.pack(side="left")
    tk.Button(buttons, text="Add desktop shortcut", command=shortcut_clicked, padx=12, pady=6
              ).pack(side="left", padx=(10, 0))
    remove_button = tk.Button(buttons, text="Stop blocking (remove all rules)", command=remove_clicked,
                              padx=12, pady=6)
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
    group.add_argument("--install-launcher", action="store_true",
                       help="add a menu entry and desktop shortcut for the current user (no sudo)")
    group.add_argument("--remove-launcher", action="store_true",
                       help="remove the current user's menu entry and desktop shortcut")
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
        if args.install_launcher:
            print(install_launcher())
            return 0
        if args.remove_launcher:
            print(remove_launcher())
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