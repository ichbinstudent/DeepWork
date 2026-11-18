#!/usr/bin/env bash
# Build DeepWork (or use the binaries of a release download) and install it
# system-wide. Run as your normal user; the script uses sudo (or doas, or
# run0) when it needs root.
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
DATADIR="$PREFIX/share"
# Run a command as root with sudo, doas or run0 (or $SUDO).
if [[ -z "${SUDO:-}" ]]; then
    for c in sudo doas run0; do
        command -v "$c" >/dev/null && SUDO=$c && break
    done
fi
[[ -n "${SUDO:-}" ]] || { echo "Needs sudo, doas or run0 (or set SUDO)." >&2; exit 1; }
cd "$(dirname "$0")"

if [[ $EUID -eq 0 ]]; then
    echo "Run ./install.sh as your normal user (it uses $SUDO for the system parts)." >&2
    exit 1
fi

command -v nft >/dev/null || echo "Note: nftables (nft) isn't installed; encrypted-DNS blocking and HTTPS filtering will be unavailable." >&2

if [[ -x bin/deepwork-daemon && ! -f Cargo.toml ]]; then
    # Unpacked release: the binaries are already built. Check that this
    # system has the libraries they need (GTK 4.14+, libadwaita 1.7+).
    BUILT=bin
    if ! out=$(bin/deepwork --version 2>&1); then
        echo "DeepWork can't run on this system:" >&2
        echo "$out" >&2
        echo "It needs systemd, GTK 4.14 or later and libadwaita 1.7 or later (Debian 13," >&2
        echo "Ubuntu 25.04, Fedora 42, Arch or newer). Install those, or build from source." >&2
        exit 1
    fi
else
    # Find cargo even when rustup's shims aren't on PATH.
    if ! command -v cargo >/dev/null; then
        for d in "$HOME/.cargo/bin" "$HOME"/.rustup/toolchains/stable-*/bin; do
            [[ -x "$d/cargo" ]] && PATH="$d:$PATH" && break
        done
    fi
    command -v cargo >/dev/null || { echo "cargo not found. Install Rust from https://rustup.rs" >&2; exit 1; }
    echo "==> Building (release)…"
    cargo build --release --locked
    BUILT=target/release
fi

echo "==> Installing to $PREFIX (needs root)…"
$SUDO install -Dm755 "$BUILT/deepwork" "$BINDIR/deepwork"
$SUDO install -Dm755 "$BUILT/deepwork-daemon" "$BINDIR/deepwork-daemon"
$SUDO install -Dm755 "$BUILT/deepworkctl" "$BINDIR/deepworkctl"
$SUDO install -Dm644 data/io.github.ichbinstudent.DeepWork.desktop "$DATADIR/applications/io.github.ichbinstudent.DeepWork.desktop"
$SUDO install -Dm644 assets/icon.svg "$DATADIR/icons/hicolor/scalable/apps/io.github.ichbinstudent.DeepWork.svg"
$SUDO install -Dm644 data/io.github.ichbinstudent.DeepWork-autostart.desktop /etc/xdg/autostart/io.github.ichbinstudent.DeepWork-autostart.desktop
# Files from versions that used the app id io.github.deepwork.DeepWork.
$SUDO rm -f "$DATADIR/applications/io.github.deepwork.DeepWork.desktop" \
    "$DATADIR/icons/hicolor/scalable/apps/io.github.deepwork.DeepWork.svg" \
    /etc/xdg/autostart/io.github.deepwork.DeepWork-autostart.desktop
# The uninstaller and the licenses stay with the program.
$SUDO install -Dm755 uninstall.sh "$PREFIX/lib/deepwork/uninstall.sh"
$SUDO install -Dm644 LICENSE "$DATADIR/doc/deepwork/LICENSE"
if [[ -f THIRD-PARTY-NOTICES.txt ]]; then
    $SUDO install -Dm644 THIRD-PARTY-NOTICES.txt "$DATADIR/doc/deepwork/THIRD-PARTY-NOTICES.txt"
fi
sed "s|@BINDIR@|$BINDIR|" data/deepwork.service | $SUDO tee /etc/systemd/system/deepwork.service >/dev/null

# Only the installing user (and root) may control the daemon.
if [[ ! -f /etc/deepwork/config.json ]]; then
    $SUDO install -d -m755 /etc/deepwork
    printf '{\n  "allowed_users": [%s]\n}\n' "$(id -u)" | $SUDO tee /etc/deepwork/config.json >/dev/null
fi

$SUDO gtk-update-icon-cache -q -t "$DATADIR/icons/hicolor" 2>/dev/null || true
$SUDO update-desktop-database -q "$DATADIR/applications" 2>/dev/null || true

echo "==> Starting the service…"
$SUDO systemctl daemon-reload
$SUDO systemctl enable deepwork.service >/dev/null
$SUDO systemctl restart deepwork.service

# Start the top-bar indicator now instead of waiting for the next login.
if [[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]] && ! pgrep -x deepwork >/dev/null; then
    setsid "$BINDIR/deepwork" --background >/dev/null 2>&1 < /dev/null &
fi

echo
echo "DeepWork is installed. Open it from your app menu or run: deepwork"
echo "Command line: deepworkctl status"
echo "To uninstall: $PREFIX/lib/deepwork/uninstall.sh [--purge]"
