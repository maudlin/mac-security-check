# mac-security-check

A one-screen macOS security check for collecting device evidence (e.g. for ISO 27001) from Macs that aren't managed by an MDM.

- **All checks pass:** prints an evidence table showing each built-in macOS command and its verbatim output, ready to screenshot.
- **Anything fails:** prints a plain-English checklist with step-by-step fixes and why each one matters.

It needs no `sudo` and changes no settings. Every run writes a record, `posture-<serial>-<date>.json`, to a `mac-security-check` folder on the Desktop. The record holds the device, user, macOS build, script version, and each check's value and result. In `--company` mode it also writes an installed-apps list there. Send the folder with the screenshot.

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

For audit evidence, replace `main` with a commit SHA so everyone runs the same version.

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
