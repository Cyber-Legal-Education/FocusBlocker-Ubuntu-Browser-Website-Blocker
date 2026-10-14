# FocusBlocker.py — Beginner’s Line-by-Line Guide

I’ll explain the file in the same order it appears. Some lines are grouped because they are one idea. Think of this as “what each part is doing, and why.”

---

## 1. Shebang and docstring

```python
#!/usr/bin/python3 -I
```

- `#!` is a **shebang**.
- It tells Linux to run this file with `/usr/bin/python3`.
- `-I` means **isolated mode**. Python will ignore user environment settings and will not automatically import modules from the folder where this script lives. That is a security feature, because the script may later run as root.

```python
"""FocusBlocker for Ubuntu: hosts-file website blocking + browser process guard.
...
"""
```

- This is the module docstring.
- It explains what the program does, how to install it, how to run it, and how to remove it.
- The most important warning: this is a practical distraction blocker, **not** a tamper-proof security system.

---

## 2. Future import and safe imports

```python
from __future__ import annotations
```

- This changes how Python handles type hints.
- It lets the code use modern type hint syntax like `list[str]` without evaluating it immediately.
- It helps compatibility with older Python versions.

```python
import os
import sys
```

- `os` gives access to the operating system: files, permissions, processes, `/proc`, etc.
- `sys` gives access to Python’s runtime, like `sys.path` and standard input/output.

```python
if os.geteuid() == 0:
    _script_dirs = {"", os.path.dirname(os.path.abspath(__file__)),
                    os.path.dirname(os.path.realpath(__file__))}
    sys.path[:] = [p for p in sys.path if p not in _script_dirs]
```

- `os.geteuid() == 0` checks if the program is running as **root**.
- If it is root, this removes the script’s own directory from `sys.path`.
- Why? If a malicious file named `json.py` or `base64.py` sits next to this script, Python might import it. Running that as root would be dangerous.
- `sys.path[:] = [...]` replaces the import search path in place.

Then come many standard-library imports:

```python
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
```

Beginner meanings:

- `argparse` — builds command-line options like `--install`.
- `contextlib` — helps write context managers and ignore errors.
- `errno` — named system error numbers, like `ESRCH` meaning “no such process.”
- `fcntl` — file locking, used to prevent two operations at once.
- `ipaddress` — checks if something is an IP address.
- `json` — reads/writes JSON config.
- `re` — regular expressions, used for parsing text.
- `shlex` — safely quotes shell command pieces.
- `shutil` — finds executables like `pkexec`.
- `signal` — sends Unix signals like SIGTERM and SIGKILL.
- `stat` — interprets file permission bits.
- `subprocess` — runs other programs like `systemctl` and `pkexec`.
- `tempfile` — makes temporary files safely.
- `time` — time tracking and sleeping.
- `Path` — friendly object for file paths.
- `Any`, `Iterable` — type hints.
- `urlsplit` — splits URLs into parts.

---

## 3. Global constants

```python
__version__ = "2.0.0"
APP_NAME = "FocusBlocker"
```

- Version number and app name.

```python
HOSTS_FILE = Path("/etc/hosts")
HOSTS_BACKUP = Path("/etc/hosts.focusblocker.original")
HOSTS_BEGIN = "# BEGIN FOCUSBLOCKER MANAGED BLOCK"
HOSTS_END = "# END FOCUSBLOCKER MANAGED BLOCK"
```

- `/etc/hosts` is the system file that maps hostnames to IP addresses.
- FocusBlocker writes its blocked domains between the BEGIN and END marker comments.
- The backup file stores the original hosts content before FocusBlocker first changes it.

```python
CONFIG_DIR = Path("/etc/focusblocker")
CONFIG_FILE = CONFIG_DIR / "config.json"
LIB_DIR = Path("/usr/local/lib/focusblocker")
INSTALLED_SCRIPT = LIB_DIR / "focusblocker.py"
UNIT_FILE = Path("/etc/systemd/system/focusblocker-browser-guard.service")
UNIT_NAME = "focusblocker-browser-guard.service"
POLICY_FILE = Path("/usr/share/polkit-1/actions/org.focusblocker.policy")
LOCK_FILE = Path("/run/focusblocker.lock")
```

- These are system locations.
- `config.json` stores the user’s chosen domains and toggles.
- The installed script lives under `/usr/local/lib/focusblocker/`.
- The systemd unit runs the browser guard daemon.
- The polkit policy controls the authentication prompt.
- The lock file prevents two root operations from running at the same time.

```python
MAX_DOMAINS = 10_000
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
GUARD_INTERVAL = 1.0
KILL_GRACE_SECONDS = 5.0
```

- Maximum 10,000 domains.
- Maximum 2 MB of JSON from the GUI.
- Browser guard scans every 1 second.
- After SIGTERM, wait 5 seconds before SIGKILL.

```python
BROWSER_DOWNLOAD_DOMAINS = [
    "download.mozilla.org",
    ...
]
```

- Optional extra domains for browser download/package servers.
- Best-effort only. May affect other software from the same vendor.

```python
BROWSER_EXACT_NAMES = frozenset({
    "firefox", "firefox-esr", ...
})
```

- Exact process names that count as browsers.
- `frozenset` is an immutable set. It is fast for membership checks.
- The comment explains that prefix matching was removed because it caught non-browsers like `chrome_crashpad_handler`, `chromedriver`, and `chromium-bsu`.

```python
_MATCH_NAMES = BROWSER_EXACT_NAMES | {n[:15] for n in BROWSER_EXACT_NAMES if len(n) > 15}
```

- Linux truncates `/proc/<pid>/comm` to 15 characters.
- So this adds shortened versions of long names.
- `|` combines two sets.

```python
BROWSER_EXE_DIRS = (
    "/usr/lib/firefox/", ...
)
```

- If a process executable lives under one of these directories, it is treated as that browser.
- This catches helper processes too.

```python
MULTI_PART_SUFFIXES = frozenset({
    "co.uk", "org.uk", ...
})
```

- Some domains have two-part public suffixes, like `co.uk`.
- This helps decide if `bbc.co.uk` is an apex domain.

```python
DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
```

- A regular expression that validates one part of a hostname.
- It allows letters, numbers, and hyphens, but not at the start or end.

```python
POLICY_XML = f"""..."""
```

- This is the polkit policy file content.
- It defines the action `org.focusblocker.apply`.
- It requires administrator authentication.
- It tells polkit that the allowed program is the installed copy of this script.

---

## 4. Custom error class

```python
class FocusBlockerError(RuntimeError):
    """Raised for recoverable app/system errors."""
```

- A custom exception.
- Used when something goes wrong but the program can explain it nicely.

---

## 5. Domain handling

### `_is_ip_address`

```python
def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
```

- Tries to parse the string as an IP address.
- If it fails, it is not an IP.
- If it succeeds, it is an IP.

### `_to_ascii_hostname`

```python
def _to_ascii_hostname(hostname: str) -> str:
    if hostname.isascii():
        return hostname
    try:
        import idna
    except ImportError:
        return hostname.encode("idna").decode("ascii")
    return idna.encode(hostname, uts46=True).decode("ascii")
```

- Converts international domain names to ASCII/punycode.
- Example: `münchen.de` becomes `xn--mnchen-3ya.de`.
- It prefers the optional `idna` package because it matches browsers better.
- If not installed, it uses Python’s built-in IDNA codec.

### `normalize_domain`

```python
def normalize_domain(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Enter a website hostname or URL.")
    if value.startswith("*."):
        raise ValueError("Wildcard domains are not supported ...")
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
```

- Strips whitespace.
- Rejects empty input.
- Rejects wildcards like `*.example.com` because `/etc/hosts` does not support wildcards.
- Adds `//` if no scheme is present, so `urlsplit` can parse it.
- Extracts the hostname from a URL.
- Removes trailing dot, lowercases.
- Converts to ASCII/punycode.
- Rejects IP addresses.
- Rejects names longer than 253 characters or with no dot.
- Splits into labels and validates each label.
- Rejects numeric top-level domains.
- Rejects localhost.
- Returns the clean hostname.

### `parse_domain_lines`

```python
def parse_domain_lines(text: str) -> list[str]:
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
```

- Splits the GUI text box into lines.
- Removes comments starting with `#`.
- Skips blank lines.
- Normalizes each domain.
- Uses a dictionary to keep only unique domains.
- Sorts the result.
- If a line is invalid, the error includes the line number.

### `_is_apex_domain`

```python
def _is_apex_domain(domain: str) -> bool:
    labels = domain.split(".")
    suffix_len = 2 if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES else 1
    return len(labels) == suffix_len + 1
```

- Checks if a domain is an apex/registrable domain.
- `example.com` is apex.
- `bbc.co.uk` is apex because `co.uk` is a multi-part suffix.
- `www.example.com` is not apex.

### `expand_domain_hosts`

```python
def expand_domain_hosts(domains: list[str]) -> list[str]:
    result: set[str] = set()
    for raw in domains:
        domain = normalize_domain(raw)
        result.add(domain)
        if _is_apex_domain(domain) and not domain.startswith("www."):
            result.add("www." + domain)
    return sorted(result)
```

- Normalizes each domain.
- Adds it to a set.
- If it is an apex domain, also adds `www.` version.
- Example: `example.com` becomes `example.com` and `www.example.com`.
- Returns sorted unique hostnames.

---

## 6. Browser process matching

### `is_browser_name`

```python
def is_browser_name(name: str) -> bool:
    base = os.path.basename(name.strip()).lower()
    if base.endswith(" (deleted)"):
        base = base[:-len(" (deleted)")]
    return base in _MATCH_NAMES
```

- Takes a process name.
- Gets the base filename, lowercases it.
- Removes `" (deleted)"` if present.
- Checks if it is in the known browser names.

### `is_browser_exe`

```python
def is_browser_exe(path: str) -> bool:
    path = path.strip()
    if path.endswith(" (deleted)"):
        path = path[:-len(" (deleted)")]
    return is_browser_name(path) or path.startswith(BROWSER_EXE_DIRS)
```

- Checks if an executable path is a known browser binary.
- Also checks if it lives in a known browser install directory.

### `_read_small`

```python
def _read_small(path: str, limit: int = 256) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        return os.read(fd, limit).decode("utf-8", "ignore").strip()
    finally:
        os.close(fd)
```

- Opens a file for reading.
- Reads at most `limit` bytes.
- Decodes as UTF-8, ignoring bad characters.
- Always closes the file.

### `_browser_process_name`

```python
def _browser_process_name(pid_text: str) -> str | None:
    try:
        exe = os.readlink(f"/proc/{pid_text}/exe")
    except FileNotFoundError:
        return None
    except OSError:
        exe = ""
    if exe and is_browser_exe(exe):
        return os.path.basename(exe)
    try:
        comm = _read_small(f"/proc/{pid_text}/comm")
    except OSError:
        return None
    return comm if comm and is_browser_name(comm) else None
```

- Looks at `/proc/<pid>/exe` to see the executable path.
- If the process is gone, returns `None`.
- If permission is denied, falls back to the `comm` file.
- If the executable path matches a browser, returns its basename.
- Otherwise reads `/proc/<pid>/comm`.
- If that matches a browser name, returns it.
- Otherwise returns `None`.

### `_signal_process`

```python
def _signal_process(pid: int, pid_text: str, sig: int) -> None:
    pidfd = None
    if hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
        try:
            pidfd = os.pidfd_open(pid)
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                return
            pidfd = None
    try:
        if pidfd is not None:
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
```

- Tries to use `pidfd` if the kernel supports it.
- A `pidfd` is a safe handle to a process. It prevents accidentally signaling a reused PID.
- If `pidfd_open` says the process does not exist, returns.
- If `pidfd` is available, re-checks that the process is still a browser, then sends the signal.
- Otherwise falls back to `os.kill`.
- Ignores errors like “process already gone.”
- Always closes the `pidfd`.

### `guard_pass`

```python
def guard_pass(self_pid: int, tracked: dict[int, float], now: float,
               pids: Iterable[str] | None = None) -> None:
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
```

- One scan of all processes.
- Lists numeric entries in `/proc`.
- Skips PID 1 and itself.
- Checks if each process is a browser.
- If it is a new browser process, records the time and sends SIGTERM.
- If it has survived longer than the grace period, sends SIGKILL.
- Removes PIDs that are no longer running from the tracking dictionary.

### `_guard_config_enabled`

```python
def _guard_config_enabled(prev_sig: tuple | None, prev_enabled: bool) -> tuple[bool, tuple | None]:
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
```

- Checks if the config file exists.
- Builds a signature from modification time, inode, and size.
- If the signature has not changed, returns the previous setting.
- Refuses to trust the config if it is not root-owned or is writable by group/others.
- Loads JSON.
- Returns `True` only if `block_browsers` is exactly `True`.

### `browser_guard_loop`

```python
def browser_guard_loop() -> int:
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
```

- Main loop for the systemd daemon.
- Verifies it is running from the trusted installed copy.
- Gets its own PID.
- Keeps a dictionary of tracked browser PIDs and first-seen times.
- Repeatedly checks config.
- If blocking is enabled, runs a guard pass.
- If disabled, clears tracking.
- Sleeps 1 second.
- This function never returns during normal operation.

---

## 7. `/etc/hosts` rendering

### `has_managed_hosts_block`

```python
def has_managed_hosts_block(text: str) -> bool:
    return any(line.strip() in (HOSTS_BEGIN, HOSTS_END) for line in text.split("\n"))
```

- Returns `True` if the hosts text contains either marker line.

### `strip_managed_hosts_block`

```python
def strip_managed_hosts_block(text: str) -> str:
    lines = text.split("\n")
    starts = [i for i, line in enumerate(lines) if line.strip() == HOSTS_BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == HOSTS_END]
    if not starts and not ends:
        return text
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise FocusBlockerError(...)
    del lines[starts[0]:ends[0] + 1]
    return "\n".join(lines)
```

- Splits text into lines.
- Finds marker line numbers.
- If no markers exist, returns the text unchanged.
- If markers are missing, duplicated, or reversed, raises an error.
- Deletes the block including markers.
- Joins lines back together.

### `render_hosts`

```python
def render_hosts(existing_text: str, domains: list[str]) -> str:
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
```

- Chooses line ending style: CRLF or LF.
- Removes any old FocusBlocker block.
- Expands domains, adding `www.` for apex domains.
- If no domains, returns the base text without a managed block.
- Otherwise builds a new block.
- For each host, adds an IPv4 line `0.0.0.0 host` and an IPv6 line `:: host`.
- Adds BEGIN and END markers.
- Joins everything with the correct line ending.
- Preserves all other hosts file content.

### `_strict_bool`

```python
def _strict_bool(payload: dict[str, Any], key: str) -> bool:
    value = payload.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"'{key}' must be true or false.")
    return value
```

- Reads a boolean setting.
- Rejects values that are not real booleans.

### `validate_payload`

```python
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
```

- Ensures the payload is a dictionary.
- Ensures `domains` is a list of strings.
- Enforces the maximum number of domains.
- Normalizes, deduplicates, and sorts domains.
- Validates the two boolean options.
- Returns a clean config dictionary.

### `blocked_domains_for_payload`

```python
def blocked_domains_for_payload(config: dict[str, Any]) -> list[str]:
    result = set(config["domains"])
    if config["include_download_domains"]:
        result.update(BROWSER_DOWNLOAD_DOMAINS)
    return sorted(result)
```

- Starts with the user’s domains.
- If the download option is enabled, adds `BROWSER_DOWNLOAD_DOMAINS`.
- Returns a sorted unique list.

---

## 8. Privileged filesystem and service helpers

### `_require_root`

```python
def _require_root() -> None:
    if os.geteuid() != 0:
        raise FocusBlockerError("System changes require administrator permissions.")
```

- Raises an error if not running as root.

### `_installed_script_problem`

```python
def _installed_script_problem() -> str | None:
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
```

- Checks the installed script and its directory.
- They must exist.
- They must not be symlinks.
- They must be owned by root.
- They must not be writable by group or others.
- The script must be a regular file.
- Returns `None` if everything is fine, otherwise a problem message.

### `_require_trusted_install`

```python
def _require_trusted_install() -> None:
    _require_root()
    problem = _installed_script_problem()
    if problem:
        raise FocusBlockerError(f"{problem} Install it with: sudo python3 <path-to>/focusblocker.py --install")
    if os.path.realpath(__file__) != os.path.realpath(INSTALLED_SCRIPT):
        raise FocusBlockerError(
            f"Privileged actions only run from the installed copy ({INSTALLED_SCRIPT}), "
            f"not from {os.path.realpath(__file__)}.")
```

- Requires root.
- Requires a safe installed copy.
- Requires that the currently running script is that installed copy.
- This prevents running privileged actions from a random downloaded file.

### `_fsync_dir`

```python
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
```

- Opens a directory.
- Forces pending filesystem changes to disk with `fsync`.
- Ignores errors if not supported.
- Closes the directory.

### `_atomic_write`

```python
def _atomic_write(path: Path, content: str | bytes, mode: int = 0o644, uid: int = 0, gid: int = 0) -> None:
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
```

- Converts text to bytes if needed.
- Creates the parent directory.
- Creates a temporary file in the same directory.
- Sets permissions before writing data.
- Changes owner to root if running as root.
- Writes, flushes, and fsyncs.
- Atomically renames the temp file over the real path.
- On error, deletes the temp file.
- Fsyncs the directory.

Atomic write means readers never see a half-written file.

### `_exclusive_lock`

```python
@contextlib.contextmanager
def _exclusive_lock(timeout: float = 30.0):
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
        os.close(fd)
```

- Opens a lock file.
- Tries to get an exclusive non-blocking lock.
- If another process has the lock, waits and retries until timeout.
- Yields control to the `with` block.
- Closing the file releases the lock.

### `_run_systemctl`

```python
def _run_systemctl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    command = ["/usr/bin/systemctl", *args]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "systemctl failed").strip()
        raise FocusBlockerError(f"Command failed ({' '.join(command)}): {detail}")
    return result
```

- Runs `systemctl` with the given arguments.
- Captures output.
- If `check=True` and it fails, raises an error with details.
- Returns the result.

### `_hosts_target`

```python
def _hosts_target() -> Path:
    return Path(os.path.realpath(HOSTS_FILE))
```

- Resolves `/etc/hosts` to its real path.
- This follows symlinks instead of replacing them.

### `_read_hosts`

```python
def _read_hosts() -> str:
    try:
        return _hosts_target().read_bytes().decode("utf-8", "surrogateescape")
    except FileNotFoundError:
        return ""
```

- Reads `/etc/hosts` as bytes and decodes it.
- `surrogateescape` preserves unusual bytes.
- If missing, returns empty string.

### `_write_hosts`

```python
def _write_hosts(text: str) -> None:
    target = _hosts_target()
    try:
        st = target.stat()
        mode, uid, gid = stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid
    except FileNotFoundError:
        mode, uid, gid = 0o644, 0, 0
    _atomic_write(target, text, mode, uid, gid)
```

- Gets current permissions and owner of `/etc/hosts`.
- If missing, uses `0644`, root, root.
- Writes atomically with the same permissions and owner.

### `_flush_dns`

```python
def _flush_dns() -> None:
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(["/usr/bin/resolvectl", "flush-caches"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False, timeout=15)
```

- Runs `resolvectl flush-caches` to clear DNS cache.
- Ignores any errors.

### `_unit_text`

```python
def _unit_text() -> str:
    return f"""[Unit]
...
"""
```

- Returns the systemd service file content.
- Important directives:
  - `ExecStart=/usr/bin/python3 -I {INSTALLED_SCRIPT} --daemon` — runs the installed script in daemon mode.
  - `Restart=always` — restarts if it crashes.
  - `User=root` — runs as root.
  - Many hardening options: `ProtectSystem`, `ProtectHome`, `PrivateTmp`, etc.
  - `CapabilityBoundingSet=CAP_KILL CAP_SYS_PTRACE` — only allows killing processes and reading process info.

### `_install_browser_service`

```python
def _install_browser_service() -> None:
    _atomic_write(UNIT_FILE, _unit_text(), 0o644)
    _run_systemctl("daemon-reload")
    _run_systemctl("enable", UNIT_NAME)
    _run_systemctl("restart", UNIT_NAME)
```

- Writes the systemd unit file.
- Reloads systemd.
- Enables the service at boot.
- Restarts it now.

### `_remove_browser_service`

```python
def _remove_browser_service() -> None:
    _run_systemctl("disable", "--now", UNIT_NAME, check=False)
    try:
        UNIT_FILE.unlink(missing_ok=True)
    finally:
        _run_systemctl("daemon-reload", check=False)
        _run_systemctl("reset-failed", UNIT_NAME, check=False)
```

- Disables and stops the service.
- Deletes the unit file.
- Reloads systemd.
- Clears failed state.

### `_ensure_lib_dir`

```python
def _ensure_lib_dir() -> None:
    if LIB_DIR.is_symlink():
        raise FocusBlockerError(f"{LIB_DIR} is a symlink; refusing to use it.")
    LIB_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(LIB_DIR, 0, 0)
    os.chmod(LIB_DIR, 0o755)
```

- Refuses if the library directory is a symlink.
- Creates it if needed.
- Sets owner to root.
- Sets permissions to `0755`.

### `_read_bytes_or_none`

```python
def _read_bytes_or_none(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None
```

- Reads a file as bytes.
- Returns `None` if it does not exist.

### `_rollback`

```python
def _rollback(original_hosts: str, previous_config: bytes | None, unit_existed: bool) -> None:
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
```

- Best-effort undo after a failed apply.
- Restores original hosts.
- Restores previous config, or deletes it if there was none.
- Removes the service if it did not exist before.

---

## 9. Privileged entry points

### `apply_system_config`

```python
def apply_system_config(raw_payload: dict[str, Any]) -> str:
    _require_root()
    config = validate_payload(raw_payload)
    all_domains = blocked_domains_for_payload(config)

    with _exclusive_lock():
        original_hosts = _read_hosts()
        updated_hosts = render_hosts(original_hosts, all_domains)

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
                browser_msg = "Browser guard enabled ..."
            else:
                _remove_browser_service()
                browser_msg = "Browser guard disabled."
        except Exception as exc:
            _rollback(original_hosts, previous_config, unit_existed)
            raise FocusBlockerError(f"Applying settings failed and was rolled back: {exc}") from exc

    _flush_dns()
    return f"Applied {len(all_domains)} hostname(s). {browser_msg}"
```

- Requires root.
- Validates the GUI payload.
- Builds the final domain list.
- Takes the exclusive lock.
- Reads current hosts.
- Renders new hosts.
- Saves a one-time backup of the original hosts if needed.
- Saves previous config and service state.
- Writes hosts, config, and service.
- On failure, rolls back.
- Flushes DNS.
- Returns a success message.

### `remove_all_system_rules`

```python
def remove_all_system_rules() -> str:
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
```

- Requires root.
- Locks.
- Removes the managed hosts block.
- Removes the browser guard service.
- Deletes config file and directory if empty.
- Flushes DNS.
- Keeps the hosts backup.

### `install_system`

```python
def install_system() -> str:
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
```

- Requires root.
- Finds the real path of this script.
- Ensures the library directory exists.
- If not already installed there, copies itself there.
- Refuses to install a world-writable source file.
- Writes the polkit policy.
- Tries to restart the service.
- Returns instructions.

### `uninstall_system`

```python
def uninstall_system() -> str:
    _require_root()
    message = remove_all_system_rules()
    for path in (INSTALLED_SCRIPT, POLICY_FILE):
        path.unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        LIB_DIR.rmdir()
    return message + " The installed script and polkit policy were removed."
```

- Requires root.
- Removes rules and service.
- Deletes installed script and polkit policy.
- Removes library directory if empty.
- Returns a message.

---

## 10. GUI code

### `_load_existing_config`

```python
def _load_existing_config() -> dict[str, Any] | None:
    try:
        return validate_payload(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return None
```

- Tries to read and validate the saved config.
- Returns `None` if missing or invalid.

### `_run_privileged`

```python
def _run_privileged(args: list[str], payload: str | None = None, timeout: float = 300.0) -> tuple[int, str, str]:
    pkexec = "/usr/bin/pkexec" if os.access("/usr/bin/pkexec", os.X_OK) else (shutil.which("pkexec") or "pkexec")
    stdin_args: dict[str, Any] = {"input": payload} if payload is not None else {"stdin": subprocess.DEVNULL}
    result = subprocess.run([pkexec, str(INSTALLED_SCRIPT), *args], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, **stdin_args)
    return result.returncode, (result.stdout or "").strip(), (result.stderr or "").strip()
```

- Finds `pkexec`.
- Runs the installed script with root privileges through polkit.
- Sends JSON payload on stdin if provided.
- Captures return code, stdout, stderr.

### `_describe_failure`

```python
def _describe_failure(code: int, out: str, err: str) -> str:
    if code == 126 and not (out or err):
        return "Authentication was cancelled."
    if code == 127 and not (out or err):
        return "Not authorized, or no polkit authentication agent is running."
    return err or out or f"pkexec exited with code {code}."
```

- Converts pkexec exit codes into friendly messages.

### `launch_gui`

```python
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
```

- Refuses to run the GUI as root.
- Imports Tkinter and threading helpers.
- If Tkinter is missing, prints install instructions.

The rest of `launch_gui`:

- Checks if FocusBlocker is installed.
- Loads existing config.
- Creates the main window.
- Adds title, labels, text box, checkboxes, warning note, status label.
- Creates a queue for background thread results.
- Defines `set_busy` to disable buttons while waiting.
- Defines `run_async` to run privileged commands in a background thread.
- Defines `poll` to check for results.
- Defines `apply_clicked` to parse domains, confirm, and send config.
- Defines `remove_clicked` to confirm and remove rules.
- Creates Apply and Remove buttons.
- Starts the Tkinter main loop.

The GUI never changes system files directly. It asks `pkexec` to run the installed root-owned copy.

---

## 11. Command-line interface

### `_read_payload_from_stdin`

```python
def _read_payload_from_stdin() -> dict[str, Any]:
    data = sys.stdin.buffer.read(MAX_PAYLOAD_BYTES + 1)
    if len(data) > MAX_PAYLOAD_BYTES:
        raise FocusBlockerError("The configuration supplied by the GUI is too large.")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise FocusBlockerError("Could not decode configuration supplied by the GUI.") from exc
    return payload
```

- Reads JSON from standard input.
- Enforces maximum size.
- Decodes and parses JSON.
- Raises a friendly error on failure.

### `main`

```python
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ubuntu local website and browser blocker")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--install", action="store_true", ...)
    group.add_argument("--uninstall", action="store_true", ...)
    group.add_argument("--apply-system", action="store_true", help=argparse.SUPPRESS)
    group.add_argument("--remove-system", action="store_true", help=argparse.SUPPRESS)
    group.add_argument("--daemon", action="store_true", help=argparse.SUPPRESS)
    group.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    args = parser.parse_args(argv)
```

- Creates the argument parser.
- Only one of these options can be used at a time.
- Hidden options are used internally by the GUI/systemd.

Then:

```python
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
```

- Dispatches to the correct function.
- Catches expected errors and prints them.
- Returns exit code 1 on error.

### Entry point

```python
if __name__ == "__main__":
    raise SystemExit(main())
```

- If run as a script, calls `main()`.
- `SystemExit` makes the exit code work correctly.

---

## 12. How a typical run works

### One-time install

1. User runs:
   ```bash
   sudo python3 focusblocker.py --install
   ```
2. Script copies itself to `/usr/local/lib/focusblocker/focusblocker.py`.
3. Writes polkit policy.
4. Restarts browser guard service if present.

### Normal GUI use

1. User runs:
   ```bash
   python3 focusblocker.py
   ```
2. GUI opens as normal user.
3. User enters domains and toggles options.
4. GUI calls `pkexec` to run the installed script with `--apply-system`.
5. Polkit asks for password.
6. Root copy validates payload.
7. Root copy writes `/etc/hosts` and config.
8. If browser blocking is on, root copy installs/starts systemd service.
9. DNS cache is flushed.

### Browser guard daemon

1. systemd runs:
   ```bash
   /usr/bin/python3 -I /usr/local/lib/focusblocker/focusblocker.py --daemon
   ```
2. Daemon reads `/etc/focusblocker/config.json`.
3. If `block_browsers` is true, it scans `/proc`.
4. It sends SIGTERM to browser processes.
5. If they survive 5 seconds, it sends SIGKILL.

### Remove everything

1. User clicks “Remove all FocusBlocker rules” or runs:
   ```bash
   sudo python3 focusblocker.py --uninstall
   ```
2. Managed hosts block is removed.
3. Service is disabled and deleted.
4. Config is removed.
5. Installed script and polkit policy are deleted.
6. Backup `/etc/hosts.focusblocker.original` is kept.

---

## 13. Review: strengths and limitations

### Strengths

- **Privilege separation:** GUI runs unprivileged. Only the installed root-owned copy makes system changes.
- **Polkit integration:** Uses `pkexec` and a polkit policy instead of `sudo` in the GUI.
- **Atomic writes:** `/etc/hosts` and config are written safely with temp file + rename.
- **Root-owned trust checks:** Refuses to run privileged actions from a random script.
- **Hosts block markers:** Only removes its own section, preserving other `/etc/hosts` entries.
- **Exact browser matching:** Avoids many false positives from prefix matching.
- **PID safety:** Uses `pidfd` when available to avoid killing a reused PID.
- **Systemd hardening:** Service uses many sandboxing options.
- **Backup:** Keeps a one-time original hosts backup.

### Limitations

- `/etc/hosts` blocks exact hostnames, not wildcard subdomains.
- A determined admin can bypass it.
- Does not block VPNs, DNS-over-HTTPS, or alternate mirrors.
- Browser list may miss renamed, portable, or new browsers.
- Brave is intentionally not in the browser name list.
- Browser download domain blocking may affect other software.
- Root can always edit `/etc/hosts` manually.
- The GUI depends on Tkinter and polkit.

---

## 14. Simple mental model

Think of FocusBlocker as three parts:

1. **GUI:** A friendly window that collects websites and options.
2. **Root helper:** The installed script that actually edits `/etc/hosts` and manages systemd.
3. **Daemon:** A root service that watches for browser processes and kills them when enabled.

The GUI asks for permission. The root helper does the dangerous work. The daemon enforces the browser rule continuously.

That is the whole program in one sentence.
