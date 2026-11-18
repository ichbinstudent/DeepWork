# Releasing DeepWork

## What the pipeline does

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`:

1. Checks that the tag matches the version in `Cargo.toml`.
2. Builds the Linux programs on Debian 13 (the oldest supported system) and packages them:
   `.deb`, `.rpm`, the `.tar.gz` with `install.sh`, and the debug information.
3. Builds the Windows app natively for x64 and ARM64 (MSYS2), the service and `deepworkctl`
   (MSVC), stamps version information and manifests into them, and builds one installer per
   architecture, plus the debug symbols.
4. Tests the exact files to be published: the `.deb` on Debian 13, the `.rpm` on Fedora 42, and
   each installer on a Windows runner of its architecture (install, block, update with a locked
   block, refused uninstall, uninstall).
5. Writes `SHA256SUMS`, signed build provenance (once the repository is public), and a **draft**
   release with this version's section of `CHANGELOG.md`. The debug symbols (for reading crash
   reports) aren't published: they stay with the workflow run as the `debug-symbols-vX.Y.Z`
   artifact for 90 days; download and keep them if needed longer.

Running the workflow by hand (*Actions → Release → Run workflow*) builds and tests everything
without publishing. Tags with a hyphen (`v0.2.0-rc.1`) become pre-releases; set the same version
in `Cargo.toml` for them.

Repository settings the pipeline uses:

- `PACKAGE_MAINTAINER` (variable): the maintainer of the Linux packages, as
  `Name <address>`. Without it the packages say `maintainer@deepwork.invalid`.

## Release day

1. Freeze changes. Make sure CI is green on `main`.
2. Update `CHANGELOG.md` (move *Unreleased* into a new version section), the version in
   `Cargo.toml` (`cargo update -w` refreshes `Cargo.lock`) and the `<releases>` in
   `data/io.github.ichbinstudent.DeepWork.metainfo.xml`. Commit.
3. Run the release workflow by hand and install the release candidates from its artifacts on real
   machines (see the manual checks below).
4. Tag the commit (`git tag vX.Y.Z && git push origin vX.Y.Z`) and wait for the draft release.
5. Download every file of the draft, check them against `SHA256SUMS`, and install each one once
   on a clean machine.
6. Finish the release notes (supported systems, known limitations) and publish the draft.
7. Update package manifests and repositories (winget, AUR, APT/RPM repositories) once they exist.
8. Watch new issues for a few days; be ready to ship a fix release.

## Manual checks before a release

CI covers installing, blocking, updating and uninstalling on Windows 11 ARM64, Windows Server
2025 x64, Debian 13 and Fedora 42. By hand, at least once per release:

- Windows 11 x64 and ARM64 on real hardware: install, the tray icon and its menu, notifications,
  a block in Chrome, Edge and Firefox, sleep and resume, a restart with a running block,
  uninstall from *Settings → Apps*. A standard user with an administrator-installed copy.
- Linux: GNOME (with the AppIndicator extension) and KDE Plasma, Wayland and X11: the tray icon,
  notifications, Freeze, app blocking, hardcore mode ending (also with the service stopped).
- Microsoft Defender (and one other antivirus) with every filter list.

## Urgent fixes

Fix on `main` (or a `release/X.Y` branch from the tag when `main` has moved on), bump the patch
version, add a changelog entry and release as above. Patch releases only fix bugs, so they can
skip the long manual checks except where the fix touches.

## How users hear about new versions

DeepWork doesn't check for updates itself (it never contacts anything; see
[PRIVACY.md](PRIVACY.md)). New versions are announced as GitHub releases: users can follow them
with *Watch → Custom → Releases* on the repository, or the releases feed
(`https://github.com/ichbinstudent/deepwork/releases.atom`). Package repositories and winget,
once available, update DeepWork with the rest of the system.

## Still to set up

- **Code signing for Windows**: get an OV/EV code-signing certificate (as a `.pfx`) and add the
  repository secrets `WINDOWS_SIGN_PFX` (the file, base64) and `WINDOWS_SIGN_PASSWORD`. The
  release then signs the programs, the installer and the uninstaller with a timestamp
  (`.github/scripts/package-windows.ps1`; CI tests the same path with a throwaway certificate).
  Azure Trusted Signing would need its own step there instead.
- **Signed Linux packages and repositories** (an APT repository key, an RPM GPG key, or COPR/OBS).
- **winget**: a manifest in `microsoft/winget-pkgs` once the installer is signed.
- **AUR** package.
