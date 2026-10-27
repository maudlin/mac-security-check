# mac-security-check

A one-screen macOS security check for collecting device evidence (e.g. for ISO 27001) from Macs that aren't managed by an MDM.

- **All checks pass:** prints an evidence table showing each built-in macOS command and its verbatim output, ready to screenshot.
- **Anything fails:** prints a plain-English checklist with step-by-step fixes and why each one matters.

It needs no `sudo` and changes no settings. Every run, pass or fail, writes its own record, `posture-<serial>-<date>-<time>.json`, to a `mac-security-check` folder on the Desktop. Records are never overwritten, so the folder shows failed runs as well as the pass that followed the fix. Each record holds the device, user, macOS build, script version, and each check's value and result. In `--company` mode an installed-apps list goes there too. On a pass, macOS's window picker opens and the user clicks the Terminal window. The screenshot goes straight into the folder, whatever their screenshot settings. The first time, macOS may ask to let Terminal record the screen; if the user declines or presses Esc, the script tells them to take it with ⌘⇧4 instead. The user then uploads the files in the folder to wherever you collect them.

## What it does and doesn't do

- Only reads settings. It needs no admin password and changes nothing.
- Writes files only to the `mac-security-check` folder on the Desktop.
- Sends nothing anywhere. Its only network calls ask Apple for the current macOS releases (`gdmf.apple.com`), check for updates (`softwareupdate`) and, in `--company` mode, compare the clock with `time.apple.com`.
- The only things it opens are System Settings pages (when you ask it to, on a fail), the screenshot picker and the results folder.

## Run it

Open Terminal (⌘Space, type "Terminal", press Enter), paste one line and press Enter.

Contractor / personal Mac:

```sh
curl -fsSL https://raw.githubusercontent.com/maudlin/mac-security-check/main/device-posture.sh | zsh
```

Company-owned Mac:

```sh
curl -fsSL https://raw.githubusercontent.com/maudlin/mac-security-check/main/device-posture.sh | zsh -s -- --company
```

These always run the latest version. Each record and screenshot shows the script version (e.g. `v1.3`), and every version is tagged in this repo, so any record can be traced back to the exact code that produced it.

## Checks

| Check | Contractor | Company |
|---|:-:|:-:|
| macOS supported, automatic security updates on, no overdue updates (a macOS update is a warning for 14 days after Apple releases it, then a fail) | ✔ | ✔ |
| FileVault on | ✔ | ✔ |
| Login password set, automatic login off | ✔ | ✔ |
| Screen locks within 5 min (screen saver or display off, plus password delay; worst power source) | ✔ | ✔ |
| Firewall on | ✔ | ✔ |
| Anti-virus running (any listed product / a named product) | ✔ | ✔ |
| Gatekeeper and SIP on | | ✔ |
| Clock in sync with Apple's time server | | ✔ |
| Remote Login, File Sharing, Screen Sharing off | | ✔ |
| Installed applications list (saved to Desktop) | | ✔ |

Thresholds and the required anti-virus product are set in the policy block at the top of the script.

## Not covered

- **Anti-virus real-time protection.** macOS doesn't let a standard user read it: Bitdefender's settings are encrypted and its CLI needs root. The script shows the product is running and how old its definitions are. Use the anti-virus management console (e.g. Bitdefender GravityZone) as the evidence for real-time protection.
