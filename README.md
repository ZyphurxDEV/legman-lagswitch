# Legman LagSwitch

A Windows lag switch with a clean dark GUI: press a hotkey to cut your network
traffic, press it again (or release) to restore it. Works **inside games**
(including Roblox) because it reads keys by polling (`GetAsyncKeyState`), not
with a hookable keyboard bind.

## Usage
1. **Run `LagSwitch.exe`** — it asks for admin automatically (click **Yes**).
   Admin is required so the network methods work and so the bind stays readable
   while a game window is focused.
2. In the window, set:
   - **Bind key** — click *set bind key* and press any key.
   - **Mode** — `toggle` (press to cut, press again to restore) or `hold`
     (cut only while the key is held).
   - **Method** — see the three options below.
3. Click **start**. The status dot shows grey (idle), green (connected) or
   red (cut). Settings save automatically to `config.json` next to the exe.

While running:
- **Your bind** cuts / restores traffic.
- **Esc** = panic key — force-restores traffic no matter what.
- **stop** or closing the window restores traffic and cleans up automatically.
- Windows toast notifications are silenced while active (and restored after),
  so nothing pops over your game.

## Methods

| Method | What it cuts | Speed | Needs |
|--------|--------------|-------|-------|
| **FIREWALL** *(default)* | ALL traffic | instant | nothing |
| **DHCP** | ALL traffic | slow | nothing |
| **WINDIVERT** | **only Roblox** | instant | bundled driver |

- **Firewall:** flips two pre-made Windows Firewall block rules (in + out) that
  share one name, so a single `netsh` call drops all packets while cut and
  resumes the instant you restore. Works on Ethernet and Wi-Fi.
- **DHCP:** `ipconfig /release` to cut, `ipconfig /renew` to restore — the
  original approach. Slower and Ethernet-only.
- **WinDivert:** finds the Roblox process's live UDP ports and opens one
  kernel-mode WinDivert handle (`FLAG_DROP`) that drops just those packets —
  so **only Roblox lags, the rest of your PC stays online**. Closing the handle
  restores instantly. Only cuts what Roblox has open at the moment you hit the
  bind, so use it once you're in a game.

Traffic is always restored on exit: firewall rules are deleted, DHCP is renewed,
and the WinDivert handle is closed on stop and close — you can never be left
blocked.

## Building it yourself
The source is `legmanlagswitch.py` (Python + PySide6).

```
pip install -r requirements.txt
build.bat
```

`build.bat` installs the deps, bundles the WinDivert driver (`--collect-all
pydivert`) and the icon, produces `LagSwitch.exe`, and cleans up after itself.
The exe is ~42 MB because the Qt runtime and WinDivert driver are bundled.

## Uninstalling
Run **`uninstall.bat`** — it asks for confirmation, then closes the app, removes
the firewall rules (via a UAC prompt), deletes the saved settings folder
(`%APPDATA%\LegmanLagSwitch`), and re-enables Windows notifications in case a
crash left them off. `LagSwitch.exe` is left in place — delete it yourself
afterwards if you want.

## Notes
- Windows SmartScreen / antivirus may false-positive flag the exe (unsigned,
  touches the firewall and ships a kernel driver). It's built from the source in
  this repo — "More info → Run anyway" or add an exclusion. The WinDivert method
  in particular needs its driver to load; antivirus or Secure Boot can block it,
  in which case use the firewall method instead.
- Cutting your connection mid-match in online games is against their rules and
  can get you banned. It only affects your own machine; use it responsibly.
