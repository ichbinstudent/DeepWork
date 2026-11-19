# Changelog

All notable changes to DeepWork. The format follows [Keep a Changelog](https://keepachangelog.com),
and versions follow [Semantic Versioning](https://semver.org) (see
[docs/PLATFORMS.md](docs/PLATFORMS.md#versions) for what that promises).

## [Unreleased]

### Security

Fixes for problems found by code scanning:

- Without `config.json` (e.g. a Linux package installed from a root shell, where `SUDO_UID` isn't
  set), every local user could control DeepWork. Now only administrators may until users are
  added; the package also recognises installs through `doas`.
- Windows: the data folder could be prepared by a standard user before installation and keep
  their access; now a folder that doesn't belong to administrators is moved aside, and every
  permission in it is set from scratch. Lock-password hashes and the log are no longer readable
  by standard users. The installer no longer learns who started it from a file in the shared
  `Public` folder, and users who may not control DeepWork can no longer use up the service's
  connections by leaving its answers unread.
- Windows: keys that DeepWork created for browser policies are only removed when nothing else was
  put into them.
- Hardcore mode: all hardcore blocks together keep administrator rights away for at most 7 days in
  a row (chaining blocks, or turning a long session hardcore, no longer gets around it); then the
  rights come back for at least an hour.
- App blocking no longer closes processes of system accounts (services), and a program can't
  escape it by renaming itself to a protected name such as `bash`.
- HTTPS filter: every plain-HTTP request on a connection is checked, not just the first;
  connections that don't name their site are refused; the filter listens on ports chosen at
  start-up (no other user can occupy them first), limits the connections it relays, closes idle
  ones, and refuses web traffic instead of letting it through when it can't run.
- Adding websites to a locked block can no longer push its earlier websites out of the hosts
  file's subdomains or Chromium's 1,000-entry blocklist.
- Changing the time zone no longer ends a running scheduled block early.
- Firefox's encrypted DNS is only turned off while websites are blocked.
- The service no longer writes through, or reads, links in folders that non-administrators can
  change (macOS: Firefox's policy file in an app bundle a user owns).
- Windows: the app and `deepworkctl` only talk to the service's own pipe. A program that took its
  name while the service wasn't running no longer gets block passwords, and the service keeps
  enforcing blocks instead of failing to start.
- Changing the time zone and then, before the service noticed, deleting a scheduled block or
  turning its schedule off no longer gets around its lock.
- Changing the breaks of a locked block (or adding schedule time before a running window) no
  longer jumps straight into a break: a new break rhythm starts with focus.
- After 5 wrong passwords in a row for a block, everyone has to wait between guesses, from 5
  seconds doubling up to 5 minutes.
- A hosts file that can't be read is left alone, and one that isn't UTF-8 keeps its bytes; the
  service no longer touches the hosts file at all when it has nothing to add or remove.
- Firefox policies that are changed during a block are kept when it ends (only the website
  filter and encrypted DNS settings are DeepWork's while it runs), and a `policies.json` that
  isn't valid JSON is left alone.

## [0.1.0]

First release, in beta.

### Linux

- Blocks of websites and apps, with schedules, breaks, pomodoro and daily allowances.
- Website blocking through `/etc/hosts` and browser policies (Chromium family and Firefox).
- Encrypted DNS blocking, an optional HTTPS filter (by site name, nothing decrypted) and VPN
  blocking.
- Locks: random text, password, strict, until restart, protected settings and hardcore mode.
- Freeze: lock the screen for a while.
- The GTK app with statistics, a top-bar indicator and notifications; `deepworkctl` for the
  command line.

### Windows (x64 and ARM64)

- Native installers that set up the DeepWork service, the app with its notification-area icon,
  the Start menu entry and `deepworkctl`.
- Website blocking through the hosts file and browser policies in the registry (Chrome, Edge,
  Brave, Chromium) and Firefox. Open connections to newly blocked sites are cut.
- Not yet on Windows: app blocking, Freeze, network protections, the *Until restart* lock and
  hardcore mode.

### Known limitations of this beta

- The Windows installers aren't code-signed yet: SmartScreen warns about them (*More info → Run
  anyway*), and some antivirus programs may be wary of a program that edits the hosts file.
- Tested automatically on Windows 11 ARM64, Windows Server 2025 x64, Debian 13 and Fedora 42
  (including a Microsoft Defender scan), but only lightly by hand on real PCs and desktops.
  Please report what doesn't work.
- An administrator can always end a block by stopping the service; see the
  [known limitations](https://github.com/ichbinstudent/deepwork/blob/main/docs/PLATFORMS.md#known-limitations).

[Unreleased]: https://github.com/ichbinstudent/deepwork/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ichbinstudent/deepwork/releases/tag/v0.1.0
