# FocusBlocker for Ubuntu

**Version:** 2.3.0

FocusBlocker is a Python/Tkinter desktop application for blocking selected website hostnames and optionally terminating selected browser processes on Ubuntu. The GUI runs as a regular user. System changes are performed after PolicyKit (`pkexec`) authentication by a root-owned installed copy of the script.

> **Security note:** FocusBlocker is a simple distraction blocker, not a tamper-proof kiosk or security policy. A system administrator with root access can still change the operating system directly. This program is for learning; please use your best judgment when using or modifying this program.

## Features

- Adds hostnames to a managed section of `/etc/hosts`, mapped to `0.0.0.0` and `::`.
- Accepts hostnames or URLs, one per line; supports `#` comments.
- Automatically adds `www` for apex domains such as `example.com` and `example.co.uk`.
- Optionally runs a root-owned `systemd` service that scans processes about once per second and terminates recognized browser processes.
- **Brave is intentionally excluded** from the browser process guard.
- Optionally blocks selected browser download/package endpoints. This is best-effort and can affect non-browser software.
- **Timed rule lock:** after applying active blocking rules, you can lock rule changes for a selected period.
- Uses a persistent, root-owned lock state, atomic file writes, an operation lock, and best-effort rollback.
- Removes FocusBlocker-managed entries without deleting unrelated `/etc/hosts` content.
- Includes `--doctor` diagnostics for common installation and desktop-launch problems.

## Requirements

```bash
sudo apt update
sudo apt install python3 python3-tk policykit-1
```

Python 3 is required. The core uses the standard library. The optional `idna` package may improve conversion of internationalized hostnames.

## Install or update

Review the script before running it with administrator privileges. From the directory containing `focusblocker_2.3.0.py`, run:

```bash
sudo python3 focusblocker_2.3.0.py --install
```

The installer places the privileged copy at:

```text
/usr/lib/focusblocker/focusblocker.py
```

It also installs a PolicyKit action at:

```text
/usr/share/polkit-1/actions/org.focusblocker.policy
```

The installed copy is intended to be root-owned and not writable by ordinary users. Privileged actions refuse to run from a different script copy. The installer updates the installed script and refreshes the application-menu entry and icon.

## Launch

Run the GUI as your regular user—not with `sudo`:

```bash
python3 focusblocker_2.3.0.py
```

You can also launch **FocusBlocker** from the application menu or desktop shortcut.

To create or refresh a per-user application-menu entry and desktop shortcut, run as your normal user:

```bash
python3 focusblocker_2.3.0.py --install-launcher
```

To remove those per-user launchers:

```bash
python3 focusblocker_2.3.0.py --remove-launcher
```

If a newly created launcher does not respond to clicks, right-click the desktop shortcut and choose **Allow Launching** if shown. Ubuntu may need a log out/in or a system restart to refresh launcher state.

If Tkinter is missing, install it with `sudo apt install python3-tk`. If the GUI reports that the system-wide copy is not installed, run the installation command above and reopen the app.

## Use

1. Enter one hostname or URL per line, for example:

   ```text
   reddit.com
   youtube.com
   https://www.example.org/path
   # This is a comment
   ```

2. Select **Block common browser processes** if you want the browser process guard enabled. Brave is not affected by this guard.
3. Optionally select **Also block common browser download/package endpoints**.
4. Choose a value in **Lock rule changes after applying**.
5. Click **Start blocking** and authenticate when Ubuntu prompts you.

The app validates hostnames and limits the submitted list to 10,000 domains. Wildcards, IP addresses, localhost, and malformed hostnames are rejected.

## Timed rule lock (new in 2.3.0)

The timer is designed to make it harder to impulsively undo a blocking session.

Available choices in the GUI are:

- No timer
- 15 minutes
- 30 minutes
- 1 hour
- 2 hours
- 4 hours
- 8 hours
- 24 hours
- 7 days

When you apply active blocking rules with a timer selected, FocusBlocker writes a lock deadline to:

```text
/etc/focusblocker/rules-lock.json
```

This state is owned and managed by the privileged application. While the lock is active, the GUI disables rule-editing controls and the **Stop blocking (remove all rules)** action. The privileged system-change operations also check the lock, so disabling a button alone is not the enforcement mechanism. The deadline persists across closing/reopening the GUI and system restarts.

When the timer expires, the controls become available again. The lock is a deadline, not a guarantee that a website is blocked for the full period: the actual blocking behavior still depends on the configured host entries and, if selected, the browser guard.

Choosing **No timer** means no rule-change lock is set for that apply operation. If there are no active blocking rules, a timer is not needed.

**Fail-closed behavior:** if the application cannot read or validate the lock state, the GUI keeps the controls disabled and the privileged operations refuse changes rather than silently treating an uncertain lock as unlocked. Diagnose permission or state-file problems rather than deleting the lock file blindly.

**Security limitation:** this is not tamper-proof against a determined administrator with root access. An administrator can modify system files, stop services, or uninstall the application outside the GUI.

## Website-blocking limitations

- `/etc/hosts` blocks exact hostnames, not wildcard subdomains. Add each subdomain separately.
- For apex domains, the app adds the `www` hostname automatically; it does not add every possible subdomain.
- Resolver or application caches may delay the effect even though FocusBlocker attempts to flush the system resolver cache.
- This is not a network firewall. VPNs, proxies, DNS-over-HTTPS, direct IP connections, alternate resolvers, and other mechanisms may bypass hostname-based blocking.
- A site may depend on additional hostnames for media, login, or APIs.

## Browser process guard

When enabled, the app installs and enables `focusblocker-browser-guard.service`. The service runs the installed script as root in daemon mode and checks `/proc` for recognized browser executable names and known browser installation directories. It sends `SIGTERM` first and may send `SIGKILL` if a detected process remains after a five-second grace period.

The service reads its root-owned configuration and only guards browsers when `block_browsers` is exactly `true`. It restarts automatically if it exits.

The recognized list includes common browsers such as Firefox, Chromium, Chrome, Edge, Opera, Vivaldi, Nyxt, and others. **Brave is intentionally excluded.** This is process termination, not a guarantee that a browser cannot start; it may appear briefly before being terminated. Renamed or portable browsers and other web-capable applications may not be detected. Terminating a browser can lose unsaved work.

## Optional download/package endpoint blocking

The optional list includes selected Mozilla, Google, Microsoft, Vivaldi, and Opera endpoints. It cannot prevent all browser installation or download methods, mirrors, or file transfers. Some endpoints, including `packages.microsoft.com`, also serve non-browser software.

## Stop blocking / remove rules

Use the GUI's **Stop blocking (remove all rules)** action and authenticate. If a timed rule lock is active, this action remains unavailable and the privileged operation is rejected until the deadline expires.

After the lock expires, this action removes FocusBlocker's managed hosts entries, disables/removes the browser guard service, and removes the active configuration. It preserves unrelated `/etc/hosts` entries and keeps the backup.

## Uninstall completely

From the directory containing the script:

```bash
sudo python3 focusblocker_2.3.0.py --uninstall
```

This removes the active rules, browser guard service, installed script, application-menu entry and PolicyKit action. It deliberately retains:

```text
/etc/hosts.focusblocker.original
```

The backup is not automatically copied over `/etc/hosts`, because that could overwrite legitimate edits made after installation. Inspect both files before restoring anything manually.

Uninstalling requires administrator privileges and is an administrative action; the timed rule lock is intended to govern changes through FocusBlocker's normal rule-management interface, not to prevent a system administrator from uninstalling or manually changing the system.

## Useful commands

```bash
python3 focusblocker_2.3.0.py --version
python3 focusblocker_2.3.0.py --doctor
systemctl status focusblocker-browser-guard.service
journalctl -u focusblocker-browser-guard.service -n 100 --no-pager
grep -n -A30 -B2 'FOCUSBLOCKER' /etc/hosts
```

`--doctor` prints a health report covering Python/Tk availability, the graphical session, the installed script, launchers, trust metadata, and recent startup errors. The last three commands help diagnose the service and hosts-file entries. Avoid manually editing the managed section while FocusBlocker is applying changes.

## Security design notes

The code includes several defensive measures: an unprivileged GUI, `pkexec` authorization, checks on the installed script and directory ownership/permissions, removal of local script directories from Python's import path when running as root, atomic file writes, an operation lock around privileged operations, and best-effort rollback. The timed lock is checked by privileged rule-changing operations and uses root-owned persistent state.

These measures reduce some risks but are not a formal security audit. They do not stop a determined administrator with root access from editing `/etc/hosts`, changing FocusBlocker's files, stopping system services, or uninstalling the program. Review the code before installation, protect administrator credentials, and test on a machine where you can recover from a bad hosts-file or service configuration.

## Troubleshooting

**Authentication prompt does not appear:** Confirm `pkexec` is installed (`command -v pkexec`) and that a desktop PolicyKit authentication agent is running. Install the package with `sudo apt install policykit-1` if needed.

**A website still opens:** Check that the exact hostname is in `/etc/hosts`, include required subdomains, and consider caches or alternate DNS/network paths. Hostname blocking is not a firewall.

**A browser is not blocked:** Check the service status and logs, verify the GUI checkbox is enabled, and remember that only known names and installation paths are matched.

**The rule controls are disabled:** Check whether the timer is still active. The GUI displays the remaining lock time. If it displays a lock-status error, run `python3 focusblocker_2.3.0.py --doctor` and inspect the lock-state file's ownership and permissions; do not remove the file blindly.

**The desktop icon does nothing:** Run `python3 focusblocker_2.3.0.py --doctor` from a terminal in the logged-in desktop session. If the report says the shortcut is not trusted, right-click it and choose **Allow Launching**. If the launcher was just created, log out/in or restart Ubuntu.

**Brave is affected:** The current code intentionally omits Brave from the browser process names and download endpoint entries. Check for other applications or policies that may be terminating it.

## Development

The main program is `focusblocker_2.3.0.py`, with sections for domain validation, browser detection, hosts-file rendering, privileged operations, persistent lock enforcement, GUI behavior, diagnostics, and CLI handling.

After reviewing changes, update the installed copy by running:

```bash
sudo python3 focusblocker_2.3.0.py --install
```

Then reopen the GUI. The installer attempts to restart an existing browser-guard service so it does not keep running an older daemon.

## License

None. This is for fun.
