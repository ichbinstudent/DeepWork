# Changelog

All notable changes to DeepWork. The format follows [Keep a Changelog](https://keepachangelog.com),
and versions follow [Semantic Versioning](https://semver.org) (see
[docs/PLATFORMS.md](docs/PLATFORMS.md#versions) for what that promises).

## [Unreleased]

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

[Unreleased]: https://github.com/ichbinstudent/deepwork/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ichbinstudent/deepwork/releases/tag/v0.1.0
