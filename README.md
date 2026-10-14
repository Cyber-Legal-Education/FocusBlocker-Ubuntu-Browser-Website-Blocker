# FocusBlocker for Ubuntu

A small Python/Tkinter application to test in VSCodium. It can:

1. Block chosen website hostnames by maintaining a dedicated section in `/etc/hosts`.
2. Optionally run a root-owned `systemd` service that repeatedly terminates common browser processes. Brave is intentionally allowed.
3. Optionally add a starter list of other browser download/package endpoints to the hostname block list. The Brave APT repository is not included in that list.
4. Remove its own rules without deleting unrelated `/etc/hosts` entries.

## Important limitations

This is a **practical distraction blocker, not tamper-proof security software**.

- `/etc/hosts` blocks exact hostnames only. It does not support wildcard domains. Add subdomains separately (for example, `example.com`, `www.example.com`, and `news.example.com`).
- Browser blocking is implemented by a system service that terminates known browser executables shortly after they start. Brave is explicitly exempt and should remain usable while browser blocking is enabled. New, portable, renamed, or unrecognized browsers may get around the process-name list.
- DNS-over-HTTPS, VPNs, direct IP addresses, alternate mirrors, and manually changing system configuration can bypass these controls.
- A user with administrator (`sudo`) access can disable or remove the service. No local app can reliably enforce these rules against an administrator who controls the machine.
- The optional download-host list is not comprehensive and may affect other software. In particular, `packages.microsoft.com` also distributes non-browser Microsoft Linux packages.

For stronger enforcement, use a separate standard (non-admin) user account, keep administrator credentials private, and apply centrally managed firewall/AppArmor/package policies. Do not rely on this prototype for child safety, workplace compliance, or other security-critical use.

## Requirements

- Ubuntu with `systemd`
- Python 3
- `python3-tk` for the GUI
- `pkexec` and a working PolicyKit authentication agent for the elevation prompt

Install the GUI dependency if needed:

```bash
sudo apt update
sudo apt install python3-tk policykit-1
```

## Run it from VSCodium

1. Extract the project folder.
2. Open the folder in VSCodium.
3. Open a terminal in the project folder.
4. Optionally run the unit tests first:

   ```bash
   python3 -m unittest discover -s tests -v
   ```

5. Start the GUI:

   ```bash
   python3 focusblocker.py
   ```

6. Enter one website hostname or URL per line. Leave comment lines beginning with `#` out of the list.
7. Choose whether to block browser processes and whether to include the optional browser-download endpoints.
8. Click **Apply system-wide** and authenticate when Ubuntu asks. The app will make a one-time backup at `/etc/hosts.focusblocker.original` before its first host-file change.

The first line in the text area is an example; replace `example.com` with the domain you actually want to block.

## Remove the rules

Open the GUI and click **Remove all FocusBlocker rules**. This removes only the marked block inserted by FocusBlocker from `/etc/hosts`, then disables and removes the FocusBlocker browser service. It keeps the original backup file.

You can also inspect status from a terminal:

```bash
systemctl status focusblocker-browser-guard.service
sudo cat /etc/hosts
sudo cat /etc/focusblocker/config.json
```

## Test carefully

Start with a harmless test domain such as `example.com`. Confirm the managed block appears in `/etc/hosts`, then verify that the domain no longer resolves as expected. Test browser blocking only after saving work in any open browser. The guard will terminate recognized browsers while enabled, but it intentionally permits Brave. If an older version of the guard is already installed, click **Apply system-wide** after updating the code so the service copies in the new version
