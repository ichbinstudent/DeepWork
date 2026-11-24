# Supported systems, features and versions

## Supported systems

| | Supported | Notes |
| --- | --- | --- |
| **Windows** | Windows 11, and Windows 10 22H2 (build 19045) or later | x64 and ARM64, each with its own native installer. Windows Server may work but isn't supported. |
| **Linux** | x86_64 with systemd, GTK 4.14+ and libadwaita 1.7+ | Tested on Arch/CachyOS. Expected to work on Debian 13+, Ubuntu 25.04+, Fedora 42+ and current rolling distributions. |
| **Linux desktops** | GNOME, KDE Plasma, and others with StatusNotifierItem tray support | On GNOME the tray icon needs the AppIndicator extension; without it the app still works, it just quits when its window closes. |
| **Browsers** | Chrome, Edge, Brave, Chromium, Vivaldi (Linux), Firefox | Every browser is covered by the hosts file. The Chromium family also gets an enterprise URL blocklist, and Firefox gets a policy file at its next start. |
| **Experimental** | macOS | Built from source with `macos/install.sh`; no download yet. Not tested: it compiles, but it may not work. |
| **Not supported** | Linux on ARM (aarch64), 32-bit systems | aarch64 Linux can be built from source but isn't tested. |

Immutable Linux distributions (Fedora Atomic, SteamOS, Bazzite) aren't supported by the install
script: it writes to `/usr/local` and `/etc`. Flatpak, Snap and AppImage can't install a system
service, so DeepWork isn't offered in those formats.

## Features per platform

The service reports what it can do on each system. The app hides or disables everything else,
and the service refuses it.

| Feature | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Website blocking (hosts file) | ✅ | ✅ | ✅ |
| Cutting off sites that are already open | ✅ | ✅ | — |
| Browser policies (URL blocklist, secure DNS off) | ✅ | ✅ | Firefox only |
| App blocking | ✅ | ✅ | ✅ |
| Encrypted DNS blocking, HTTPS filter, VPN blocking | ✅ | — | — |
| Freeze (lock the screen) | ✅ | — | — |
| Locks: random text, password, strict, protected settings | ✅ | ✅ | ✅ |
| *Until restart* lock | ✅ | — | ✅ |
| Hardcore lock | ✅ | — | — |
| Tray icon | ✅ | ✅ | — |
| Running-app picker | ✅ | ✅ | — |

### Known limitations

**Both:**
- A user with administrator (root) rights can always end a block: stop the service, edit the
  hosts file, or uninstall DeepWork once the lock is over. DeepWork makes giving up harder; it
  can't make it impossible for an administrator. Use a standard account for everyday work, or
  hardcore mode on Linux.
- Browsers that use their own encrypted DNS or a proxy can get around the hosts file. DeepWork
  turns secure DNS off in the browsers it manages policies for, and on Linux it also blocks
  well-known encrypted-DNS servers. Proxy and VPN extensions in the Chromium family and Firefox are
  covered by the URL blocklist.
- A page that is already open loses its connection when a block starts, but its tab stays open
  (it shows the site's own "offline" state until it is reloaded).
- Schedules follow the computer's time zone (on Windows any user may change it). Changing it
  doesn't end a scheduled block that is running, but later scheduled times move with it.

**Windows:**
- Freeze, the network protections, the *Until restart* lock and hardcore mode aren't
  available yet.
- The installer isn't code-signed yet, so Windows SmartScreen warns about it.
- Locks only stop standard users: an administrator can stop the DeepWork service.
- Programs that were open when a block starts are asked to close, and closed after 3 seconds if
  they don't; unsaved work in them is lost. Programs running as administrator can't be asked.
- Web apps that Chrome or Edge installed run in the browser, so they can't be blocked as apps
  (block their website instead).

**Linux:**
- Hardcore mode removes administrator rights through sudo, doas, polkit and the root password.
  Other ways to become root (a root shell left open, `su` with another password, physical access)
  aren't covered.

## Beta

DeepWork 0.x is **beta** on both systems: complete for everyday use, but not yet widely tested.
On Windows, *beta* also means the installer isn't code-signed yet and DeepWork has had little
testing on real PCs. The label is used the same way in the README, the app's About dialog and the
release notes.

## Versions

DeepWork follows [Semantic Versioning](https://semver.org).

- **Patch** releases (0.1.1) only fix bugs.
- **Minor** releases (0.2.0) add features. While the major version is 0, they may also change the
  command-line tool's output and the protocol between the app and the service. The app and the
  service of the same release always work together; after an update the app asks to be reopened
  if an older copy is still running.
- **Stored data** (blocks, locks, schedules, statistics, settings) is never lost in an update.
  Every release reads the data of all earlier releases. The state file has a format number, and a
  release that finds data from a newer release refuses to start instead of overwriting it.
- **Downgrades** aren't supported: the Windows installer refuses them, and on Linux an older
  service refuses data written by a newer one.
- Running locks stay locked through an update.
- DeepWork doesn't check for updates itself. New versions are published as
  [GitHub releases](https://github.com/ichbinstudent/deepwork/releases); follow them with
  *Watch → Custom → Releases*, or the releases feed.
