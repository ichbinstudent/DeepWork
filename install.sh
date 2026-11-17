#!/usr/bin/env bash
# Build DeepWork and install it system-wide. Run as your normal user;
# the script asks for sudo when it needs it.
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
DATADIR="$PREFIX/share"
cd "$(dirname "$0")"

if [[ $EUID -eq 0 ]]; then
    echo "Run ./install.sh as your normal user (it uses sudo for the system parts)." >&2
    exit 1
fi

# Find cargo even when rustup's shims aren't on PATH.
if ! command -v cargo >/dev/null; then
    for d in "$HOME/.cargo/bin" "$HOME"/.rustup/toolchains/stable-*/bin; do
        [[ -x "$d/cargo" ]] && PATH="$d:$PATH" && break
    done
fi
command -v cargo >/dev/null || { echo "cargo not found. Install Rust from https://rustup.rs" >&2; exit 1; }

command -v nft >/dev/null || echo "Note: nftables (nft) isn't installed; encrypted-DNS blocking and HTTPS filtering will be unavailable." >&2

echo "==> Building (release)…"
cargo build --release --locked

echo "==> Installing to $PREFIX (needs sudo)…"
sudo install -Dm755 target/release/deepwork "$BINDIR/deepwork"
sudo install -Dm755 target/release/deepwork-daemon "$BINDIR/deepwork-daemon"
sudo install -Dm755 target/release/deepworkctl "$BINDIR/deepworkctl"
sudo install -Dm644 data/io.github.ichbinstudent.DeepWork.desktop "$DATADIR/applications/io.github.ichbinstudent.DeepWork.desktop"
sudo install -Dm644 assets/icon.svg "$DATADIR/icons/hicolor/scalable/apps/io.github.ichbinstudent.DeepWork.svg"
sudo install -Dm644 data/io.github.ichbinstudent.DeepWork-autostart.desktop /etc/xdg/autostart/io.github.ichbinstudent.DeepWork-autostart.desktop
# Files from versions that used the app id io.github.deepwork.DeepWork.
sudo rm -f "$DATADIR/applications/io.github.deepwork.DeepWork.desktop" \
    "$DATADIR/icons/hicolor/scalable/apps/io.github.deepwork.DeepWork.svg" \
    /etc/xdg/autostart/io.github.deepwork.DeepWork-autostart.desktop
sed "s|@BINDIR@|$BINDIR|" data/deepwork.service | sudo tee /etc/systemd/system/deepwork.service >/dev/null

# Only the installing user (and root) may control the daemon.
if [[ ! -f /etc/deepwork/config.json ]]; then
    sudo install -d -m755 /etc/deepwork
    printf '{\n  "allowed_users": [%s]\n}\n' "$(id -u)" | sudo tee /etc/deepwork/config.json >/dev/null
fi

sudo gtk-update-icon-cache -q -t "$DATADIR/icons/hicolor" 2>/dev/null || true
sudo update-desktop-database -q "$DATADIR/applications" 2>/dev/null || true

echo "==> Starting the service…"
sudo systemctl daemon-reload
sudo systemctl enable deepwork.service >/dev/null
sudo systemctl restart deepwork.service

# Start the top-bar indicator now instead of waiting for the next login.
if [[ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ]] && ! pgrep -x deepwork >/dev/null; then
    setsid "$BINDIR/deepwork" --background >/dev/null 2>&1 < /dev/null &
fi

echo
echo "DeepWork is installed. Open it from your app menu or run: deepwork"
echo "Command line: deepworkctl status"
